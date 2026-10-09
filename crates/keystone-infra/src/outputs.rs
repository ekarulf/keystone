//! Reading the ARNs back out of a deployment.
//!
//! `cdk deploy --outputs-file cdk-outputs.json` writes a map of stack name to
//! output map. Keystone reads it rather than calling CloudFormation, so
//! synchronizing a profile needs no AWS credentials at all — the file the operator
//! already has is enough.
//!
//! Parsing is strict about shape and about values: an ARN of the wrong resource
//! type written into a profile produces a `CreateSession` failure that names
//! neither the field nor the file it came from.

use std::collections::BTreeMap;
use std::path::Path;

use keystone_core::error::{KeystoneError, Result};

use crate::plan::validate_arn;

/// The output names the generated stack declares.
const TRUST_ANCHOR_ARN: &str = "TrustAnchorArn";
const PROFILE_ARN: &str = "RolesAnywhereProfileArn";
const ROLE_ARN: &str = "RoleArn";
const REGION: &str = "Region";

/// The deployed ARNs a Keystone profile needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackOutputs {
    /// Which stack in the outputs file these came from.
    pub stack_name: String,
    pub trust_anchor_arn: String,
    pub roles_anywhere_profile_arn: String,
    pub role_arn: String,
    /// Present when the stack was deployed to a resolved region.
    pub region: Option<String>,
    /// The device key id the stack was generated for, when the stack reports it.
    ///
    /// Used to refuse synchronizing outputs from one device's stack into another
    /// device's profile.
    pub key_id: Option<String>,
}

impl StackOutputs {
    /// Parse `cdk-outputs.json`.
    ///
    /// `stack_name` selects a stack when the file holds more than one; with a
    /// single stack it may be `None`.
    pub fn parse(json: &str, stack_name: Option<&str>) -> Result<Self> {
        let root: serde_json::Value = serde_json::from_str(json).map_err(|error| {
            KeystoneError::InvalidConfiguration(format!(
                "the CDK outputs file is not valid JSON: {error}"
            ))
        })?;

        let stacks = root.as_object().ok_or_else(|| {
            KeystoneError::InvalidConfiguration(
                "the CDK outputs file should be an object mapping stack names to outputs"
                    .to_string(),
            )
        })?;

        let (found_name, outputs) = match stack_name {
            Some(wanted) => {
                let outputs = stacks.get(wanted).ok_or_else(|| {
                    let available: Vec<&str> = stacks.keys().map(String::as_str).collect();
                    KeystoneError::InvalidConfiguration(format!(
                        "the CDK outputs file has no stack named {wanted:?}; it contains {}",
                        if available.is_empty() {
                            "no stacks".to_string()
                        } else {
                            available.join(", ")
                        }
                    ))
                })?;
                (wanted.to_string(), outputs)
            }
            None => {
                let mut entries = stacks.iter();
                let (name, outputs) = entries.next().ok_or_else(|| {
                    KeystoneError::InvalidConfiguration(
                        "the CDK outputs file is empty; was the deployment run with \
                         --outputs-file?"
                            .to_string(),
                    )
                })?;
                if entries.next().is_some() {
                    let available: Vec<&str> = stacks.keys().map(String::as_str).collect();
                    return Err(KeystoneError::InvalidConfiguration(format!(
                        "the CDK outputs file contains several stacks ({}); name the one to \
                         read with --stack-name",
                        available.join(", ")
                    )));
                }
                (name.clone(), outputs)
            }
        };

        let fields = outputs.as_object().ok_or_else(|| {
            KeystoneError::InvalidConfiguration(format!(
                "the outputs for stack {found_name:?} should be an object of output name to value"
            ))
        })?;

        let string_field = |name: &str| -> Result<String> {
            let value = fields.get(name).ok_or_else(|| {
                KeystoneError::InvalidConfiguration(format!(
                    "stack {found_name:?} has no {name} output. Deploy the project Keystone \
                     generated, or add the output to a hand-written stack."
                ))
            })?;
            value
                .as_str()
                .map(str::to_string)
                .filter(|text| !text.trim().is_empty())
                .ok_or_else(|| {
                    KeystoneError::InvalidConfiguration(format!(
                        "the {name} output of stack {found_name:?} is not a non-empty string"
                    ))
                })
        };

        let trust_anchor_arn = string_field(TRUST_ANCHOR_ARN)?;
        let roles_anywhere_profile_arn = string_field(PROFILE_ARN)?;
        let role_arn = string_field(ROLE_ARN)?;

        // Each ARN checked against the resource type it will be used as, because a
        // profile written with a swapped pair fails much later and less clearly.
        validate_arn(&trust_anchor_arn, "rolesanywhere", "trust-anchor")?;
        validate_arn(&roles_anywhere_profile_arn, "rolesanywhere", "profile")?;
        validate_arn(&role_arn, "iam", "role")?;

        let optional = |name: &str| -> Option<String> {
            fields
                .get(name)
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .filter(|text| !text.trim().is_empty())
        };

        Ok(Self {
            stack_name: found_name,
            trust_anchor_arn,
            roles_anywhere_profile_arn,
            role_arn,
            region: optional(REGION),
            key_id: optional("KeystoneKeyId"),
        })
    }

    /// Parse an outputs file from disk.
    pub fn read(path: &Path, stack_name: Option<&str>) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                KeystoneError::InvalidConfiguration(format!(
                    "{} does not exist. Deploy with `cdk deploy --outputs-file {}`.",
                    path.display(),
                    path.file_name()
                        .map(|name| name.to_string_lossy().to_string())
                        .unwrap_or_else(|| "cdk-outputs.json".to_string())
                ))
            } else {
                KeystoneError::io(format!("cannot read {}", path.display()), error)
            }
        })?;
        Self::parse(&text, stack_name)
    }

    /// The region the outputs claim, if it is a resolved region rather than a
    /// CloudFormation token.
    ///
    /// A stack synthesized without an explicit `env.region` outputs the literal
    /// `${Token[AWS.Region.4]}`; writing that into a profile would produce an
    /// unresolvable endpoint.
    pub fn resolved_region(&self) -> Option<&str> {
        self.region
            .as_deref()
            .filter(|region| !region.contains("${Token") && !region.contains("AWS::Region"))
    }

    /// The fields to write into a profile, as (field name, value) pairs.
    pub fn profile_fields(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::new();
        fields.insert("trust_anchor_arn", self.trust_anchor_arn.clone());
        fields.insert(
            "roles_anywhere_profile_arn",
            self.roles_anywhere_profile_arn.clone(),
        );
        fields.insert("role_arn", self.role_arn.clone());
        if let Some(region) = self.resolved_region() {
            fields.insert("region", region.to_string());
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRUST_ANCHOR: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/1111";
    const RA_PROFILE: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/2222";
    const ROLE: &str = "arn:aws:iam::123456789012:role/ExampleDeviceRole";

    fn outputs_json(stack: &str) -> String {
        format!(
            r#"{{
              "{stack}": {{
                "TrustAnchorArn": "{TRUST_ANCHOR}",
                "RolesAnywhereProfileArn": "{RA_PROFILE}",
                "RoleArn": "{ROLE}",
                "Region": "us-east-1",
                "KeystoneKeyId": "01JZKEYSTONEDEVICE00000001",
                "DeviceSanUri": "urn:keystone:device:01JZKEYSTONEDEVICE00000001"
              }}
            }}"#
        )
    }

    #[test]
    fn the_arns_the_generated_stack_emits_are_read() {
        let outputs = StackOutputs::parse(&outputs_json("ExampleDeviceRole"), None).unwrap();
        assert_eq!(outputs.stack_name, "ExampleDeviceRole");
        assert_eq!(outputs.trust_anchor_arn, TRUST_ANCHOR);
        assert_eq!(outputs.roles_anywhere_profile_arn, RA_PROFILE);
        assert_eq!(outputs.role_arn, ROLE);
        assert_eq!(outputs.resolved_region(), Some("us-east-1"));
        assert_eq!(
            outputs.key_id.as_deref(),
            Some("01JZKEYSTONEDEVICE00000001")
        );
    }

    #[test]
    fn a_named_stack_is_selected_out_of_several() {
        let json = format!(
            r#"{{"Other": {{"TrustAnchorArn": "nope"}},
                 "KeystoneWork": {{"TrustAnchorArn": "{TRUST_ANCHOR}",
                                   "RolesAnywhereProfileArn": "{RA_PROFILE}",
                                   "RoleArn": "{ROLE}"}}}}"#
        );
        let outputs = StackOutputs::parse(&json, Some("KeystoneWork")).unwrap();
        assert_eq!(outputs.stack_name, "KeystoneWork");
        assert_eq!(outputs.region, None);
    }

    #[test]
    fn several_stacks_without_a_name_is_an_error_that_lists_them() {
        // Guessing would be worse than asking: the wrong stack's ARNs are valid
        // ARNs, so the mistake would surface as an authorization failure.
        let json = format!(
            r#"{{"KeystoneWork": {{"TrustAnchorArn": "{TRUST_ANCHOR}"}},
                 "ExampleDeviceRole": {{"TrustAnchorArn": "{TRUST_ANCHOR}"}}}}"#
        );
        let error = StackOutputs::parse(&json, None).unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("KeystoneWork"), "{message}");
        assert!(message.contains("ExampleDeviceRole"), "{message}");
        assert!(message.contains("--stack-name"), "{message}");
    }

    #[test]
    fn a_missing_stack_name_lists_what_is_available() {
        let error = StackOutputs::parse(&outputs_json("ExampleDeviceRole"), Some("KeystoneWork"))
            .unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("KeystoneWork"), "{message}");
        assert!(message.contains("ExampleDeviceRole"), "{message}");
    }

    #[test]
    fn a_missing_output_names_the_output_and_says_what_to_do() {
        let json = format!(
            r#"{{"ExampleDeviceRole": {{"TrustAnchorArn": "{TRUST_ANCHOR}",
                                       "RoleArn": "{ROLE}"}}}}"#
        );
        let error = StackOutputs::parse(&json, None).unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("RolesAnywhereProfileArn"), "{message}");
    }

    #[test]
    fn an_arn_of_the_wrong_resource_type_is_refused() {
        // The realistic failure: a hand-written stack that outputs the profile ARN
        // under TrustAnchorArn.
        let json = format!(
            r#"{{"ExampleDeviceRole": {{"TrustAnchorArn": "{RA_PROFILE}",
                                       "RolesAnywhereProfileArn": "{RA_PROFILE}",
                                       "RoleArn": "{ROLE}"}}}}"#
        );
        let error = StackOutputs::parse(&json, None).unwrap_err();
        assert!(format!("{error}").contains("trust-anchor"), "{error}");
    }

    #[test]
    fn an_unresolved_region_token_is_not_treated_as_a_region() {
        // A stack synthesized without env.region outputs a token. Writing it into a
        // profile would produce an endpoint that cannot be resolved.
        let json = format!(
            r#"{{"ExampleDeviceRole": {{"TrustAnchorArn": "{TRUST_ANCHOR}",
                                       "RolesAnywhereProfileArn": "{RA_PROFILE}",
                                       "RoleArn": "{ROLE}",
                                       "Region": "${{Token[AWS.Region.4]}}"}}}}"#
        );
        let outputs = StackOutputs::parse(&json, None).unwrap();
        assert!(outputs.region.is_some());
        assert_eq!(outputs.resolved_region(), None);
        assert!(!outputs.profile_fields().contains_key("region"));
    }

    #[test]
    fn junk_and_empty_files_are_reported_clearly() {
        for (json, expected) in [
            ("not json", "not valid JSON"),
            ("[]", "mapping stack names"),
            ("{}", "empty"),
        ] {
            let error = StackOutputs::parse(json, None).unwrap_err();
            assert!(format!("{error}").contains(expected), "{json}: {error}");
        }
    }

    #[test]
    fn an_empty_output_value_is_refused() {
        let json = format!(
            r#"{{"ExampleDeviceRole": {{"TrustAnchorArn": "  ",
                                       "RolesAnywhereProfileArn": "{RA_PROFILE}",
                                       "RoleArn": "{ROLE}"}}}}"#
        );
        let error = StackOutputs::parse(&json, None).unwrap_err();
        assert!(format!("{error}").contains("non-empty"), "{error}");
    }

    #[test]
    fn a_missing_outputs_file_says_how_to_produce_one() {
        let error = StackOutputs::read(
            std::path::Path::new("/nonexistent/keystone/cdk-outputs.json"),
            None,
        )
        .unwrap_err();
        assert!(format!("{error}").contains("--outputs-file"), "{error}");
    }
}
