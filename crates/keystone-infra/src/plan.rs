//! What to generate.
//!
//! A [`CdkPlan`] is the validated, fully-resolved answer to "which resources,
//! named what, with which permissions". Building one is where every rule about
//! the generated infrastructure is enforced — the templates downstream only
//! substitute text, so a check that is not here is not made at all.
//!
//! The rules:
//!
//! * `AdministratorAccess` is never attached ([`PermissionMode::managed`]);
//! * the default is a role with no workload permissions;
//! * an externally managed role is referenced, never modified;
//! * names must be legal for their AWS resource type;
//! * the plan carries no private key material.

use keystone_core::config::{Profile, MAX_DURATION_SECONDS, MIN_DURATION_SECONDS};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::{KeyId, Sha256Fingerprint};
use time::OffsetDateTime;

/// Managed policies Keystone refuses to attach.
///
/// The design forbids `AdministratorAccess` by name. The others are here because
/// they are the same mistake: a device certificate that never prompts the user is
/// a standing grant, and a standing grant of account-wide write access is not
/// something a generator should produce on request.
const FORBIDDEN_MANAGED_POLICIES: &[&str] = &[
    "AdministratorAccess",
    "IAMFullAccess",
    "PowerUserAccess",
    "AWSOrganizationsFullAccess",
];

/// Find an `Allow` statement granting every action on every resource.
///
/// Returns a 1-based index for the message, so the operator can find the statement
/// in their own file. Handles both shapes IAM accepts for `Statement` (one object
/// or an array) and both for `Action`/`Resource` (a string or an array).
///
/// Deliberately narrow: it looks for the unqualified `*` on both axes at once, not
/// for wildcards in general. `s3:*` on one bucket is a normal policy, and a
/// generator that rejected it would just get bypassed. This catches only the case
/// that is indistinguishable from `AdministratorAccess`.
///
/// A statement carrying a `Condition` is still refused. A condition can narrow the
/// grant to something reasonable, but it can also be trivially satisfiable, and
/// deciding which would mean evaluating IAM condition semantics here.
fn find_administrator_statement(statement: &serde_json::Value) -> Option<String> {
    let statements = match statement {
        serde_json::Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };

    for (index, statement) in statements.iter().enumerate() {
        // A missing `Effect` defaults to nothing in IAM — the document is invalid
        // — so only an explicit Allow is treated as one.
        let allows = statement
            .get("Effect")
            .and_then(|effect| effect.as_str())
            .is_some_and(|effect| effect.eq_ignore_ascii_case("Allow"));
        if !allows {
            continue;
        }
        // `NotAction`/`NotResource` are a different construct and are not folded
        // in here; an `Allow` with `NotAction` is unusual enough that guessing at
        // its intent would produce false rejections.
        if is_unrestricted(statement.get("Action")) && is_unrestricted(statement.get("Resource")) {
            return Some(format!("#{}", index + 1));
        }
    }
    None
}

/// Whether an `Action` or `Resource` field is the unqualified wildcard.
fn is_unrestricted(field: Option<&serde_json::Value>) -> bool {
    match field {
        Some(serde_json::Value::String(value)) => value == "*",
        // Any `*` in the list is enough: the other entries only add to the grant.
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .any(|item| item.as_str().is_some_and(|value| value == "*")),
        _ => false,
    }
}

/// Where the trust anchor comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAnchorTarget {
    /// Create one from the CA certificate held locally.
    ///
    /// Carries the PEM, which is public: it is the certificate, not the key.
    Create { ca_certificate_pem: String },
    /// Reuse an anchor that already exists, created from an organization's CA.
    Existing { arn: String },
}

/// Whether the stack owns the IAM role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleTarget {
    /// Create a role named `name` with `permissions`.
    Create {
        name: String,
        permissions: PermissionMode,
    },
    /// Reference a role managed elsewhere.
    ///
    /// The generated stack does not modify it — a CDK-owned change could drop
    /// trust relationships the stack knows nothing about — so the README carries
    /// the trust-policy statement to add by hand.
    Existing { arn: String },
}

/// What the created role is allowed to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionMode {
    /// No workload permissions. The default.
    None,
    /// An inline policy document, read from the file given to `--policy`.
    ///
    /// Held as parsed JSON so a malformed document fails at generation rather
    /// than at `cdk synth`.
    Inline { document: serde_json::Value },
    /// One or more managed policy ARNs.
    Managed { arns: Vec<String> },
}

impl PermissionMode {
    /// An inline policy from the text of a JSON file.
    pub fn inline(json: &str) -> Result<Self> {
        let document: serde_json::Value = serde_json::from_str(json).map_err(|error| {
            KeystoneError::InvalidConfiguration(format!("policy file is not valid JSON: {error}"))
        })?;
        if !document.is_object() {
            return Err(KeystoneError::InvalidConfiguration(
                "policy file must contain a JSON object, an IAM policy document".to_string(),
            ));
        }
        let statement = document.get("Statement").ok_or_else(|| {
            KeystoneError::InvalidConfiguration(
                "policy document has no \"Statement\"; it is probably not an IAM policy"
                    .to_string(),
            )
        })?;
        // The same prohibition `managed` enforces, by the easier path. Refusing
        // `AdministratorAccess` by name while accepting a hand-written
        // `{"Action":"*","Resource":"*"}` would leave the rule cosmetic.
        if let Some(offending) = find_administrator_statement(statement) {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "policy statement {offending} allows every action on every resource, which is \
                 AdministratorAccess written out. Keystone will not attach it to a device role: a \
                 hardware-backed identity refreshes credentials without user interaction, so this \
                 would be a standing grant. Narrow the policy, or attach it yourself after \
                 deployment."
            )));
        }
        Ok(Self::Inline { document })
    }

    /// Managed policies, rejecting the ones Keystone must never attach.
    pub fn managed(arns: Vec<String>) -> Result<Self> {
        if arns.is_empty() {
            return Err(KeystoneError::InvalidConfiguration(
                "no managed policy ARNs were given".to_string(),
            ));
        }
        for arn in &arns {
            if !arn.starts_with("arn:") {
                return Err(KeystoneError::InvalidConfiguration(format!(
                    "{arn} is not an ARN; managed policies are named like \
                     arn:aws:iam::aws:policy/ReadOnlyAccess"
                )));
            }
            // Matched on the policy name, so a customer-managed policy that
            // merely mentions the word is not caught, and an AWS-managed
            // AdministratorAccess cannot slip through under a different path.
            let name = arn.rsplit('/').next().unwrap_or(arn);
            if let Some(forbidden) = FORBIDDEN_MANAGED_POLICIES
                .iter()
                .find(|f| name.eq_ignore_ascii_case(f))
            {
                return Err(KeystoneError::InvalidConfiguration(format!(
                    "Keystone will not attach {forbidden} to a device role: a hardware-backed \
                     identity refreshes credentials without user interaction, so this would be a \
                     standing grant. Attach it yourself after deployment if that is what you want."
                )));
            }
        }
        Ok(Self::Managed { arns })
    }

    /// The discriminant the templates branch on.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Inline { .. } => "inline",
            Self::Managed { .. } => "managed",
        }
    }
}

/// A validated description of the CDK project to generate.
///
/// Every field is public data. There is deliberately no field for a private key:
/// see the crate documentation.
#[derive(Debug, Clone)]
pub struct CdkPlan {
    /// The local Keystone profile this was generated from.
    pub profile_name: String,
    pub region: String,
    /// CloudFormation stack name, e.g. `KeystonePersonal`.
    pub stack_name: String,
    pub trust_anchor_name: String,
    /// The IAM Roles Anywhere profile name (not the local Keystone profile).
    pub roles_anywhere_profile_name: String,
    pub trust_anchor: TrustAnchorTarget,
    pub role: RoleTarget,
    pub duration_seconds: u32,
    pub key_id: KeyId,
    pub role_session_name: Option<String>,
    pub certificate_fingerprint: Option<Sha256Fingerprint>,
    pub ca_fingerprint: Option<Sha256Fingerprint>,
    pub certificate_expires_at: Option<OffsetDateTime>,
    /// `ephemeral-ca` or `external-ca`, which changes the README's revocation
    /// advice: disabling a one-device anchor revokes exactly one device.
    pub issuer_mode: Option<String>,
}

/// The arguments `keystone infra cdk init` collects, before validation.
///
/// Separate from [`CdkPlan`] so the CLI can hand over raw flags and get either a
/// checked plan or one clear error, rather than assembling a plan field by field
/// and validating late.
#[derive(Debug, Clone, Default)]
pub struct PlanRequest {
    pub profile_name: String,
    pub stack_name: Option<String>,
    pub role_name: Option<String>,
    pub trust_anchor_name: Option<String>,
    pub roles_anywhere_profile_name: Option<String>,
    pub existing_trust_anchor_arn: Option<String>,
    pub existing_role_arn: Option<String>,
    pub permissions: Option<PermissionMode>,
    /// Overrides the profile's duration when set.
    pub duration_seconds: Option<u32>,
    /// The CA certificate PEM, needed unless an existing anchor is reused.
    pub ca_certificate_pem: Option<String>,
}

impl CdkPlan {
    /// Resolve and validate a request against the local profile.
    pub fn build(request: PlanRequest, profile: &Profile) -> Result<Self> {
        keystone_core::config::validate_profile_name(&request.profile_name)?;
        keystone_core::config::validate_region(&profile.region)?;

        let key_id = profile
            .key_id
            .clone()
            .ok_or_else(|| KeystoneError::ProfileIncomplete {
                profile: request.profile_name.clone(),
                reason: "no device key yet, so there is no URI SAN to authorize. \
                         Run `keystone bootstrap` first."
                    .to_string(),
            })?;

        let duration_seconds = request.duration_seconds.unwrap_or(profile.duration_seconds);
        if !(MIN_DURATION_SECONDS..=MAX_DURATION_SECONDS).contains(&duration_seconds) {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "session duration must be between {MIN_DURATION_SECONDS} and \
                 {MAX_DURATION_SECONDS} seconds, found {duration_seconds}"
            )));
        }

        let default_suffix = pascal_case(&request.profile_name);
        let stack_name = request
            .stack_name
            .unwrap_or_else(|| format!("Keystone{default_suffix}"));
        validate_stack_name(&stack_name)?;

        let trust_anchor = match request.existing_trust_anchor_arn {
            Some(arn) => {
                validate_arn(&arn, "rolesanywhere", "trust-anchor")?;
                TrustAnchorTarget::Existing { arn }
            }
            None => {
                let pem = request.ca_certificate_pem.ok_or_else(|| {
                    KeystoneError::InvalidConfiguration(
                        "no CA certificate is available for the trust anchor. Either run \
                         `keystone bootstrap` first or pass --existing-trust-anchor-arn."
                            .to_string(),
                    )
                })?;
                // Parsed, not just pattern-matched: an anchor built from a
                // non-certificate fails at deploy time with an opaque error, and
                // an anchor built from the *device* certificate instead of the CA
                // would deploy and then reject every session.
                let parsed = keystone_pki::ParsedCertificate::from_pem(&pem)?;
                if !parsed.is_ca {
                    return Err(KeystoneError::InvalidConfiguration(format!(
                        "the certificate offered for the trust anchor is not a CA \
                         (subject {}); a trust anchor bundle must contain the issuing CA",
                        parsed.subject
                    )));
                }
                TrustAnchorTarget::Create {
                    ca_certificate_pem: pem,
                }
            }
        };

        let role = match request.existing_role_arn {
            Some(arn) => {
                validate_arn(&arn, "iam", "role")?;
                if request.permissions.is_some() {
                    return Err(KeystoneError::InvalidConfiguration(
                        "permissions cannot be set for an existing role: the generated stack does \
                         not modify a role it does not own"
                            .to_string(),
                    ));
                }
                if request.role_name.is_some() {
                    return Err(KeystoneError::InvalidConfiguration(
                        "--role-name and --existing-role-arn are mutually exclusive".to_string(),
                    ));
                }
                RoleTarget::Existing { arn }
            }
            None => {
                let name = request
                    .role_name
                    .unwrap_or_else(|| format!("Keystone{default_suffix}"));
                validate_role_name(&name)?;
                RoleTarget::Create {
                    name,
                    // The design's default: an empty role.
                    permissions: request.permissions.unwrap_or(PermissionMode::None),
                }
            }
        };

        let trust_anchor_name = request
            .trust_anchor_name
            .unwrap_or_else(|| format!("keystone-{}", request.profile_name));
        validate_resource_name(&trust_anchor_name, "trust anchor")?;
        let roles_anywhere_profile_name = request
            .roles_anywhere_profile_name
            .unwrap_or_else(|| format!("keystone-{}", request.profile_name));
        validate_resource_name(&roles_anywhere_profile_name, "Roles Anywhere profile")?;

        if let Some(name) = &profile.role_session_name {
            keystone_core::config::validate_role_session_name(name)?;
        }

        Ok(Self {
            profile_name: request.profile_name,
            region: profile.region.clone(),
            stack_name,
            trust_anchor_name,
            roles_anywhere_profile_name,
            trust_anchor,
            role,
            duration_seconds,
            key_id,
            role_session_name: profile.role_session_name.clone(),
            certificate_fingerprint: profile.certificate_fingerprint_sha256.clone(),
            ca_fingerprint: profile.ca_fingerprint_sha256.clone(),
            certificate_expires_at: profile.issuer.as_ref().map(|i| i.certificate_expires_at),
            issuer_mode: profile.issuer.as_ref().map(|i| match i.mode {
                keystone_core::config::IssuerMode::EphemeralCa => "ephemeral-ca".to_string(),
                keystone_core::config::IssuerMode::ExternalCa => "external-ca".to_string(),
            }),
        })
    }

    /// The device URI SAN the generated trust policy authorizes.
    pub fn device_san_uri(&self) -> String {
        self.key_id.device_san_uri()
    }

    /// The CA certificate PEM to embed, if this plan creates a trust anchor.
    pub fn ca_certificate_pem(&self) -> Option<&str> {
        match &self.trust_anchor {
            TrustAnchorTarget::Create { ca_certificate_pem } => Some(ca_certificate_pem),
            TrustAnchorTarget::Existing { .. } => None,
        }
    }

    /// The inline policy document to write, if any.
    pub fn inline_policy(&self) -> Option<&serde_json::Value> {
        match &self.role {
            RoleTarget::Create {
                permissions: PermissionMode::Inline { document },
                ..
            } => Some(document),
            _ => None,
        }
    }

    /// `KeystonePersonalStack`, the TypeScript class name.
    pub fn stack_class(&self) -> String {
        format!("{}Stack", pascal_case(&self.stack_name))
    }

    /// `keystone-personal-stack`, the module file stem.
    pub fn stack_module(&self) -> String {
        format!("{}-stack", kebab_case(&self.stack_name))
    }

    /// The npm package name, which must be lowercase.
    pub fn project_slug(&self) -> String {
        kebab_case(&self.stack_name)
    }
}

/// Convert an arbitrary profile or stack name to PascalCase.
fn pascal_case(input: &str) -> String {
    input
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                // Only the first character is forced; the rest is left alone so
                // `KeystonePersonal` does not become `Keystonepersonal`.
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Convert to kebab-case, splitting on case transitions as well as separators.
fn kebab_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    let mut previous_lower = false;
    for ch in input.chars() {
        if ch.is_ascii_uppercase() {
            if previous_lower {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
            previous_lower = false;
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
            previous_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
            previous_lower = false;
        }
    }
    out.trim_matches('-').to_string()
}

/// A CloudFormation stack name: alphanumeric and hyphens, starting with a letter.
fn validate_stack_name(name: &str) -> Result<()> {
    let invalid = |reason: &str| {
        Err(KeystoneError::InvalidConfiguration(format!(
            "stack name {name:?} is not valid: {reason}"
        )))
    };
    if name.is_empty() || name.len() > 128 {
        return invalid("CloudFormation allows 1 to 128 characters");
    }
    if !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
        return invalid("it must start with a letter");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return invalid("only letters, digits, and hyphens are allowed");
    }
    Ok(())
}

/// An IAM role name: up to 64 characters from a restricted set.
fn validate_role_name(name: &str) -> Result<()> {
    let invalid = |reason: &str| {
        Err(KeystoneError::InvalidConfiguration(format!(
            "role name {name:?} is not valid: {reason}"
        )))
    };
    if name.is_empty() || name.len() > 64 {
        return invalid("IAM allows 1 to 64 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c))
    {
        return invalid("IAM allows only alphanumerics and +=,.@_-");
    }
    Ok(())
}

/// A Roles Anywhere trust anchor or profile name.
fn validate_resource_name(name: &str, kind: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{kind} name {name:?} must be between 1 and 255 characters"
        )));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{kind} name {name:?} contains a control character"
        )));
    }
    Ok(())
}

/// Check an ARN's shape, service, and resource type.
///
/// Not a full ARN grammar — the point is to catch a profile ARN pasted where a
/// trust anchor ARN belongs, which otherwise deploys and then fails at
/// `CreateSession` with an error naming neither.
pub(crate) fn validate_arn(arn: &str, service: &str, resource_type: &str) -> Result<()> {
    let invalid = |reason: String| Err(KeystoneError::InvalidConfiguration(reason));

    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() < 6 || parts[0] != "arn" {
        return invalid(format!("{arn:?} is not an ARN"));
    }
    if parts[2] != service {
        return invalid(format!(
            "{arn:?} names the {} service, but a {service} ARN is required here",
            parts[2]
        ));
    }
    let resource = parts[5..].join(":");
    let found = resource.split('/').next().unwrap_or(&resource);
    if found != resource_type {
        return invalid(format!(
            "{arn:?} is a {found:?} ARN, but a {resource_type:?} ARN is required here"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::config::{IssuerMetadata, Profile};

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn profile() -> Profile {
        let mut profile = Profile::new("us-east-1");
        profile.key_id = Some(KeyId::parse("01JZKEYSTONEDEVICE00000001").unwrap());
        profile.issuer = Some(IssuerMetadata::ephemeral(NOW + time::Duration::days(365)));
        profile
    }

    /// A CA certificate PEM, generated rather than pasted so the test does not
    /// depend on a fixture's validity window.
    fn ca_pem() -> String {
        keystone_pki::testing::TestCa::generate().certificate_pem()
    }

    fn request() -> PlanRequest {
        PlanRequest {
            profile_name: "personal".to_string(),
            ca_certificate_pem: Some(ca_pem()),
            ..Default::default()
        }
    }

    #[test]
    fn the_default_plan_creates_an_empty_role_and_a_new_trust_anchor() {
        // The design's default: "The generated role contains no workload
        // permissions."
        let plan = CdkPlan::build(request(), &profile()).unwrap();
        assert!(matches!(
            plan.role,
            RoleTarget::Create {
                permissions: PermissionMode::None,
                ..
            }
        ));
        assert!(matches!(
            plan.trust_anchor,
            TrustAnchorTarget::Create { .. }
        ));
        assert_eq!(plan.stack_name, "KeystonePersonal");
        assert_eq!(plan.stack_class(), "KeystonePersonalStack");
        assert_eq!(plan.stack_module(), "keystone-personal-stack");
        assert_eq!(plan.project_slug(), "keystone-personal");
        assert_eq!(
            plan.device_san_uri(),
            "urn:keystone:device:01JZKEYSTONEDEVICE00000001"
        );
    }

    #[test]
    fn administrator_access_is_refused_by_name() {
        // The design's hard rule. Checked on the policy name so the partition and
        // path cannot smuggle it past.
        for arn in [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/administratoraccess",
            "arn:aws:iam::aws:policy/job-function/AdministratorAccess",
        ] {
            let error = PermissionMode::managed(vec![arn.to_string()]).unwrap_err();
            assert!(
                format!("{error}").contains("AdministratorAccess"),
                "{arn}: {error}"
            );
        }
    }

    #[test]
    fn other_account_wide_policies_are_refused_too() {
        for arn in [
            "arn:aws:iam::aws:policy/PowerUserAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
            "arn:aws:iam::aws:policy/AWSOrganizationsFullAccess",
        ] {
            assert!(
                PermissionMode::managed(vec![arn.to_string()]).is_err(),
                "{arn} should be refused"
            );
        }
    }

    #[test]
    fn a_narrow_managed_policy_is_allowed() {
        // The design's own example. Refusing everything would make the flag
        // useless.
        let mode =
            PermissionMode::managed(vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()])
                .unwrap();
        assert_eq!(mode.as_str(), "managed");
    }

    #[test]
    fn a_policy_named_like_a_forbidden_one_but_customer_managed_is_still_refused() {
        // A customer-managed policy called AdministratorAccess grants whatever
        // its author wrote, but the name is indistinguishable in a review.
        assert!(PermissionMode::managed(vec![
            "arn:aws:iam::123456789012:policy/AdministratorAccess".to_string()
        ])
        .is_err());
    }

    #[test]
    fn a_managed_policy_that_is_not_an_arn_is_refused() {
        for value in ["ReadOnlyAccess", "iam::aws:policy/ReadOnlyAccess", ""] {
            assert!(
                PermissionMode::managed(vec![value.to_string()]).is_err(),
                "{value:?} should be refused"
            );
        }
        assert!(PermissionMode::managed(Vec::new()).is_err());
    }

    #[test]
    fn an_inline_policy_must_be_an_iam_policy_document() {
        // Caught here rather than at `cdk synth`, where the error names a
        // generated file the user did not write.
        assert!(PermissionMode::inline(r#"{"Statement":[]}"#).is_ok());
        assert!(PermissionMode::inline("not json").is_err());
        assert!(PermissionMode::inline("[]").is_err());
        assert!(PermissionMode::inline(r#"{"Version":"2012-10-17"}"#).is_err());
    }

    #[test]
    fn an_inline_policy_cannot_smuggle_in_administrator_access() {
        // The prohibition `managed` enforces by name, defeated by writing it out.
        // Every shape IAM accepts, because catching only the first would leave the
        // check trivially avoidable.
        for document in [
            r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}"#,
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            r#"{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}"#,
            r#"{"Statement":[{"Effect":"Allow","Action":["s3:Get*","*"],"Resource":"*"}]}"#,
            r#"{"Statement":[{"Effect":"allow","Action":"*","Resource":"*"}]}"#,
            // Not the first statement, so the scan cannot stop at the head.
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
                             {"Effect":"Allow","Action":"*","Resource":"*"}]}"#,
            // A condition can be trivially satisfiable, so it does not rescue it.
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*",
                              "Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}"#,
        ] {
            let error = PermissionMode::inline(document)
                .expect_err(&format!("should be refused: {document}"))
                .to_string();
            assert!(error.contains("every action on every resource"), "{error}");
        }
    }

    #[test]
    fn a_policy_that_is_merely_broad_is_still_allowed() {
        // The guard has to stay narrow. A generator that refused ordinary policies
        // would be worked around rather than obeyed.
        for document in [
            // A service wildcard scoped to a resource, the common shape.
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::bucket/*"}]}"#,
            // Every action, but only on one resource.
            r#"{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::bucket"}]}"#,
            // Every resource, but only one action — how most read-only policies look.
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
            // A Deny on everything is a restriction, not a grant.
            r#"{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#,
        ] {
            assert!(
                PermissionMode::inline(document).is_ok(),
                "should be allowed: {document}"
            );
        }
    }

    #[test]
    fn an_existing_role_is_referenced_and_never_given_permissions() {
        // "It does not automatically modify an externally managed role."
        let plan = CdkPlan::build(
            PlanRequest {
                existing_role_arn: Some("arn:aws:iam::123456789012:role/Developer".to_string()),
                ..request()
            },
            &profile(),
        )
        .unwrap();
        assert!(matches!(plan.role, RoleTarget::Existing { .. }));
        assert!(plan.inline_policy().is_none());

        let error = CdkPlan::build(
            PlanRequest {
                existing_role_arn: Some("arn:aws:iam::123456789012:role/Developer".to_string()),
                permissions: Some(
                    PermissionMode::managed(vec![
                        "arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()
                    ])
                    .unwrap(),
                ),
                ..request()
            },
            &profile(),
        )
        .unwrap_err();
        assert!(format!("{error}").contains("does not modify"), "{error}");
    }

    #[test]
    fn an_existing_trust_anchor_needs_no_ca_certificate() {
        let plan = CdkPlan::build(
            PlanRequest {
                existing_trust_anchor_arn: Some(
                    "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc".to_string(),
                ),
                ca_certificate_pem: None,
                ..request()
            },
            &profile(),
        )
        .unwrap();
        assert!(matches!(
            plan.trust_anchor,
            TrustAnchorTarget::Existing { .. }
        ));
        assert!(plan.ca_certificate_pem().is_none());
    }

    #[test]
    fn an_arn_of_the_wrong_resource_type_is_refused() {
        // Pasting the Roles Anywhere profile ARN where the trust anchor belongs is
        // an easy mistake; the deployed stack would fail at CreateSession.
        let error = CdkPlan::build(
            PlanRequest {
                existing_trust_anchor_arn: Some(
                    "arn:aws:rolesanywhere:us-east-1:123456789012:profile/abc".to_string(),
                ),
                ..request()
            },
            &profile(),
        )
        .unwrap_err();
        assert!(format!("{error}").contains("trust-anchor"), "{error}");

        let error = CdkPlan::build(
            PlanRequest {
                existing_role_arn: Some("arn:aws:iam::123456789012:user/example-user".to_string()),
                ..request()
            },
            &profile(),
        )
        .unwrap_err();
        assert!(format!("{error}").contains("role"), "{error}");
    }

    #[test]
    fn an_arn_naming_the_wrong_service_is_refused() {
        let error = CdkPlan::build(
            PlanRequest {
                existing_role_arn: Some("arn:aws:sts::123456789012:role/Developer".to_string()),
                ..request()
            },
            &profile(),
        )
        .unwrap_err();
        assert!(format!("{error}").contains("sts"), "{error}");
    }

    #[test]
    fn a_device_certificate_offered_as_the_trust_anchor_bundle_is_refused() {
        // Deploys fine and then rejects every session, because the leaf cannot
        // vouch for itself.
        let bundle = keystone_pki::testing::device_bundle();
        let leaf_pem = keystone_pki::certificate::encode_pem("CERTIFICATE", bundle.leaf_der());

        let error = CdkPlan::build(
            PlanRequest {
                ca_certificate_pem: Some(leaf_pem),
                ..request()
            },
            &profile(),
        )
        .unwrap_err();
        assert!(format!("{error}").contains("not a CA"), "{error}");
    }

    #[test]
    fn a_profile_without_a_device_key_cannot_be_generated_from() {
        // There would be no URI SAN to authorize, so the generated trust policy
        // would restrict nothing.
        let mut profile = profile();
        profile.key_id = None;
        let error = CdkPlan::build(request(), &profile).unwrap_err();
        assert!(matches!(error, KeystoneError::ProfileIncomplete { .. }));
        assert!(format!("{error}").contains("bootstrap"), "{error}");
    }

    #[test]
    fn a_missing_ca_certificate_is_reported_with_both_ways_out() {
        let error = CdkPlan::build(
            PlanRequest {
                ca_certificate_pem: None,
                ..request()
            },
            &profile(),
        )
        .unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("bootstrap"), "{message}");
        assert!(message.contains("existing-trust-anchor-arn"), "{message}");
    }

    #[test]
    fn a_duration_outside_the_aws_range_is_refused() {
        for duration in [0, 899, 3601, 86400] {
            let error = CdkPlan::build(
                PlanRequest {
                    duration_seconds: Some(duration),
                    ..request()
                },
                &profile(),
            )
            .unwrap_err();
            assert!(format!("{error}").contains("duration"), "{duration}");
        }
        assert_eq!(
            CdkPlan::build(
                PlanRequest {
                    duration_seconds: Some(900),
                    ..request()
                },
                &profile()
            )
            .unwrap()
            .duration_seconds,
            900
        );
    }

    #[test]
    fn illegal_stack_and_role_names_are_refused() {
        for name in ["1Keystone", "Keystone Personal", "Keystone_Personal", ""] {
            assert!(
                CdkPlan::build(
                    PlanRequest {
                        stack_name: Some(name.to_string()),
                        ..request()
                    },
                    &profile()
                )
                .is_err(),
                "stack name {name:?} should be refused"
            );
        }
        for name in ["role name with spaces", "role/with/slashes", ""] {
            assert!(
                CdkPlan::build(
                    PlanRequest {
                        role_name: Some(name.to_string()),
                        ..request()
                    },
                    &profile()
                )
                .is_err(),
                "role name {name:?} should be refused"
            );
        }
    }

    #[test]
    fn a_long_role_name_is_refused_before_iam_truncates_it() {
        assert!(CdkPlan::build(
            PlanRequest {
                role_name: Some("K".repeat(65)),
                ..request()
            },
            &profile()
        )
        .is_err());
        assert!(CdkPlan::build(
            PlanRequest {
                role_name: Some("K".repeat(64)),
                ..request()
            },
            &profile()
        )
        .is_ok());
    }

    #[test]
    fn the_plan_records_the_issuer_mode_so_the_readme_can_describe_revocation() {
        // Revocation advice differs: a one-device ephemeral anchor can simply be
        // disabled, a shared anchor cannot.
        let plan = CdkPlan::build(request(), &profile()).unwrap();
        assert_eq!(plan.issuer_mode.as_deref(), Some("ephemeral-ca"));
        assert!(plan.certificate_expires_at.is_some());
    }

    #[test]
    fn name_conversions_handle_the_shapes_a_profile_name_can_take() {
        assert_eq!(pascal_case("personal"), "Personal");
        assert_eq!(pascal_case("work-laptop"), "WorkLaptop");
        assert_eq!(pascal_case("work_laptop_2"), "WorkLaptop2");
        assert_eq!(pascal_case("KeystonePersonal"), "KeystonePersonal");
        assert_eq!(kebab_case("KeystonePersonal"), "keystone-personal");
        assert_eq!(kebab_case("Keystone-Personal"), "keystone-personal");
        assert_eq!(kebab_case("keystone"), "keystone");
        assert_eq!(kebab_case("KeystoneV2"), "keystone-v2");
    }
}
