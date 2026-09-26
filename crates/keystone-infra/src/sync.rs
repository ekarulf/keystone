//! Writing deployed ARNs back into the local profile.
//!
//! The design's rules, in order of how surprising it would be to get them wrong:
//!
//! * "Update placeholders automatically." A freshly initialized profile holds
//!   `TBD`, and filling it in is the whole point.
//! * "Preserve matching values." Re-running `sync-profile` after a no-op deploy
//!   must not be reported as a change.
//! * "Reject conflicting existing values." A profile already pointing at a
//!   deployed trust anchor is working; overwriting it silently would break a setup
//!   that currently issues credentials.
//! * "Require `--force` to overwrite conflicts."
//! * "Write the configuration atomically."
//!
//! Nothing here contacts AWS: the input is the outputs file the operator already
//! has from `cdk deploy --outputs-file`.

use keystone_core::config::{Config, PLACEHOLDER};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::store::Store;

use crate::outputs::StackOutputs;

/// What happened to one profile field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldOutcome {
    /// The field held a placeholder and was filled in.
    Filled { value: String },
    /// The field already held exactly this value.
    Unchanged { value: String },
    /// The field held a different value and `--force` replaced it.
    Overwritten { previous: String, value: String },
    /// The field held a different value and was left alone.
    Conflict { existing: String, incoming: String },
}

impl FieldOutcome {
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }

    /// Whether the profile was modified.
    pub fn changed(&self) -> bool {
        matches!(self, Self::Filled { .. } | Self::Overwritten { .. })
    }
}

/// The result of a synchronization.
#[derive(Debug, Clone)]
pub struct SyncReport {
    pub profile_name: String,
    pub stack_name: String,
    /// One entry per field, in a stable order for display.
    pub fields: Vec<(&'static str, FieldOutcome)>,
    /// Whether the configuration file was written.
    pub saved: bool,
}

impl SyncReport {
    pub fn conflicts(&self) -> Vec<(&'static str, &FieldOutcome)> {
        self.fields
            .iter()
            .filter(|(_, outcome)| outcome.is_conflict())
            .map(|(name, outcome)| (*name, outcome))
            .collect()
    }

    pub fn has_conflicts(&self) -> bool {
        !self.conflicts().is_empty()
    }

    pub fn changed(&self) -> bool {
        self.fields.iter().any(|(_, outcome)| outcome.changed())
    }
}

/// Merge stack outputs into a profile and save the configuration.
///
/// Returns the report without saving when there is a conflict and `force` is
/// false: a partially applied sync — some ARNs from the new stack, some from the
/// old — would be worse than none, because the resulting profile would point at a
/// trust anchor that does not know the role.
pub fn sync_profile(
    store: &Store,
    profile_name: &str,
    outputs: &StackOutputs,
    force: bool,
) -> Result<SyncReport> {
    let mut config: Config = store.load_config()?;

    // Fails with `UnknownProfile` naming the profile, which is the right error:
    // `sync-profile` is not the command that creates one.
    {
        config.profile(profile_name)?;
    }

    // A stack generated for a different device would authorize a URI SAN this
    // profile's key does not present, so every session would be rejected after an
    // apparently successful sync.
    if let (Some(stack_key_id), Some(profile_key_id)) = (
        outputs.key_id.as_deref(),
        config.profile(profile_name)?.key_id.as_ref(),
    ) {
        if stack_key_id != profile_key_id.as_str() {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "stack {} was generated for device key {stack_key_id}, but profile {profile_name} \
                 uses {}. Synchronizing these would produce a profile whose certificate the \
                 deployed trust policy does not authorize.",
                outputs.stack_name,
                profile_key_id.as_str()
            )));
        }
    }

    let incoming = outputs.profile_fields();
    let mut fields = Vec::new();

    for (name, value) in &incoming {
        let existing = read_field(config.profile(profile_name)?, name);
        let outcome = if is_placeholder(&existing) {
            FieldOutcome::Filled {
                value: value.clone(),
            }
        } else if existing == *value {
            FieldOutcome::Unchanged {
                value: value.clone(),
            }
        } else if force {
            FieldOutcome::Overwritten {
                previous: existing,
                value: value.clone(),
            }
        } else {
            FieldOutcome::Conflict {
                existing,
                incoming: value.clone(),
            }
        };
        fields.push((*name, outcome));
    }

    let has_conflicts = fields.iter().any(|(_, outcome)| outcome.is_conflict());
    let should_save = !has_conflicts && fields.iter().any(|(_, outcome)| outcome.changed());

    if should_save {
        let profile = config.profile_mut(profile_name)?;
        for (name, value) in &incoming {
            write_field(profile, name, value);
        }
        // `save_config` validates before writing and writes atomically, so a
        // rejected merge cannot leave a config the next command refuses to load.
        store.save_config(&config)?;
    }

    Ok(SyncReport {
        profile_name: profile_name.to_string(),
        stack_name: outputs.stack_name.clone(),
        fields,
        saved: should_save,
    })
}

/// Whether a field is unset, in the sense the design means by "placeholder".
fn is_placeholder(value: &str) -> bool {
    value.trim().is_empty() || value == PLACEHOLDER
}

fn read_field(profile: &keystone_core::config::Profile, field: &str) -> String {
    match field {
        "trust_anchor_arn" => profile.trust_anchor_arn.clone(),
        "roles_anywhere_profile_arn" => profile.roles_anywhere_profile_arn.clone(),
        "role_arn" => profile.role_arn.clone(),
        "region" => profile.region.clone(),
        // Unreachable: the field list comes from `StackOutputs::profile_fields`.
        other => unreachable!("no profile field named {other}"),
    }
}

fn write_field(profile: &mut keystone_core::config::Profile, field: &str, value: &str) {
    match field {
        "trust_anchor_arn" => profile.trust_anchor_arn = value.to_string(),
        "roles_anywhere_profile_arn" => profile.roles_anywhere_profile_arn = value.to_string(),
        "role_arn" => profile.role_arn = value.to_string(),
        "region" => profile.region = value.to_string(),
        other => unreachable!("no profile field named {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::config::{Paths, Profile};
    use keystone_core::identity::KeyId;
    use std::path::PathBuf;

    const TRUST_ANCHOR: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/1111";
    const RA_PROFILE: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/2222";
    const ROLE: &str = "arn:aws:iam::123456789012:role/ExampleDeviceRole";
    const KEY_ID: &str = "01JZKEYSTONEDEVICE00000001";

    struct TempHome(PathBuf);

    impl TempHome {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("keystone-sync-{name}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> Store {
            Store::new(Paths::rooted_at(&self.0))
        }

        /// A store holding one profile with placeholder ARNs.
        fn with_fresh_profile(&self, name: &str) -> Store {
            let store = self.store();
            let mut config = store.load_config().unwrap();
            let mut profile = Profile::new("us-east-1");
            profile.key_id = Some(KeyId::parse(KEY_ID).unwrap());
            config.profiles.insert(name.to_string(), profile);
            store.save_config(&config).unwrap();
            store
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn outputs() -> StackOutputs {
        StackOutputs {
            stack_name: "ExampleDeviceRole".to_string(),
            trust_anchor_arn: TRUST_ANCHOR.to_string(),
            roles_anywhere_profile_arn: RA_PROFILE.to_string(),
            role_arn: ROLE.to_string(),
            region: Some("us-east-1".to_string()),
            key_id: Some(KEY_ID.to_string()),
        }
    }

    #[test]
    fn placeholders_are_filled_in_and_the_profile_becomes_usable() {
        let home = TempHome::new("fill");
        let store = home.with_fresh_profile("personal");

        let report = sync_profile(&store, "personal", &outputs(), false).unwrap();
        assert!(report.saved);
        assert!(!report.has_conflicts());
        assert!(report.fields.iter().all(|(_, outcome)| matches!(
            outcome,
            FieldOutcome::Filled { .. }
        ) || matches!(
            outcome,
            FieldOutcome::Unchanged { .. }
        )));

        let config = store.load_config().unwrap();
        let profile = config.profile("personal").unwrap();
        assert_eq!(profile.trust_anchor_arn, TRUST_ANCHOR);
        assert_eq!(profile.roles_anywhere_profile_arn, RA_PROFILE);
        assert_eq!(profile.role_arn, ROLE);
        // And the profile is now complete enough to request credentials.
        profile.require_ready("personal").unwrap();
    }

    #[test]
    fn a_second_sync_of_the_same_outputs_changes_nothing() {
        // "Preserve matching values." Re-running after a no-op deploy is routine.
        let home = TempHome::new("idempotent");
        let store = home.with_fresh_profile("personal");
        sync_profile(&store, "personal", &outputs(), false).unwrap();

        let report = sync_profile(&store, "personal", &outputs(), false).unwrap();
        assert!(!report.saved, "nothing to write");
        assert!(!report.changed());
        assert!(!report.has_conflicts());
        assert!(report
            .fields
            .iter()
            .all(|(_, outcome)| matches!(outcome, FieldOutcome::Unchanged { .. })));
    }

    #[test]
    fn a_conflicting_value_is_refused_and_nothing_is_written() {
        // "Reject conflicting existing values." The existing profile works; a
        // partial overwrite would leave ARNs from two different deployments.
        let home = TempHome::new("conflict");
        let store = home.with_fresh_profile("personal");
        sync_profile(&store, "personal", &outputs(), false).unwrap();

        let mut second = outputs();
        second.stack_name = "ExampleDeviceRoleV2".to_string();
        second.trust_anchor_arn =
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/9999".to_string();

        let report = sync_profile(&store, "personal", &second, false).unwrap();
        assert!(report.has_conflicts());
        assert!(!report.saved);
        let (name, outcome) = report.conflicts()[0];
        assert_eq!(name, "trust_anchor_arn");
        assert!(matches!(outcome, FieldOutcome::Conflict { .. }));

        // The old value survives, in full: no field was applied.
        let profile_config = store.load_config().unwrap();
        let profile = profile_config.profile("personal").unwrap();
        assert_eq!(profile.trust_anchor_arn, TRUST_ANCHOR);
        assert_eq!(profile.role_arn, ROLE);
    }

    #[test]
    fn force_overwrites_a_conflict_and_reports_the_previous_value() {
        // "Require `--force` to overwrite conflicts." The previous value is
        // reported so the operator can put it back.
        let home = TempHome::new("force");
        let store = home.with_fresh_profile("personal");
        sync_profile(&store, "personal", &outputs(), false).unwrap();

        let mut second = outputs();
        let new_anchor = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/9999";
        second.trust_anchor_arn = new_anchor.to_string();

        let report = sync_profile(&store, "personal", &second, true).unwrap();
        assert!(report.saved);
        assert!(!report.has_conflicts());
        let (_, outcome) = report
            .fields
            .iter()
            .find(|(name, _)| *name == "trust_anchor_arn")
            .unwrap();
        assert_eq!(
            outcome,
            &FieldOutcome::Overwritten {
                previous: TRUST_ANCHOR.to_string(),
                value: new_anchor.to_string(),
            }
        );

        assert_eq!(
            store
                .load_config()
                .unwrap()
                .profile("personal")
                .unwrap()
                .trust_anchor_arn,
            new_anchor
        );
    }

    #[test]
    fn a_stack_built_for_another_device_is_refused_even_with_force() {
        // The trust policy in that stack authorizes a different URI SAN, so the
        // synchronized profile would fail every CreateSession. Force is for
        // conflicting ARNs, not for the wrong device.
        let home = TempHome::new("wrong-device");
        let store = home.with_fresh_profile("personal");

        let mut other = outputs();
        other.key_id = Some("01JZKEYSTONEDEVICE00000002".to_string());

        for force in [false, true] {
            let error = sync_profile(&store, "personal", &other, force).unwrap_err();
            let message = format!("{error}");
            assert!(message.contains("01JZKEYSTONEDEVICE00000002"), "{message}");
            assert!(message.contains(KEY_ID), "{message}");
        }
    }

    #[test]
    fn an_unknown_profile_is_reported_rather_than_created() {
        // `sync-profile` records a deployment against a profile; inventing one
        // would hide a typo in the profile name.
        let home = TempHome::new("unknown");
        let store = home.with_fresh_profile("personal");
        let error = sync_profile(&store, "work", &outputs(), false).unwrap_err();
        assert!(matches!(error, KeystoneError::UnknownProfile(_)), "{error}");
    }

    #[test]
    fn the_configuration_survives_a_rejected_sync_unchanged_byte_for_byte() {
        // Atomic in the sense that matters: a refused merge does not touch the file.
        let home = TempHome::new("untouched");
        let store = home.with_fresh_profile("personal");
        sync_profile(&store, "personal", &outputs(), false).unwrap();

        let path = store.paths().config_file();
        let before = std::fs::read_to_string(&path).unwrap();

        let mut second = outputs();
        second.role_arn = "arn:aws:iam::123456789012:role/Other".to_string();
        sync_profile(&store, "personal", &second, false).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn a_region_the_stack_did_not_resolve_is_left_alone() {
        // `resolved_region` filters the token out, so the profile's region — which
        // the user chose — is not replaced by `${Token[AWS.Region.4]}`.
        let home = TempHome::new("region-token");
        let store = home.with_fresh_profile("personal");

        let mut tokened = outputs();
        tokened.region = Some("${Token[AWS.Region.4]}".to_string());
        let report = sync_profile(&store, "personal", &tokened, false).unwrap();
        assert!(!report.fields.iter().any(|(name, _)| *name == "region"));
        assert_eq!(
            store
                .load_config()
                .unwrap()
                .profile("personal")
                .unwrap()
                .region,
            "us-east-1"
        );
    }

    #[test]
    fn a_region_that_differs_is_a_conflict_like_any_other_field() {
        // Deploying to a region other than the profile's would work at
        // CreateSession and then hand back credentials for the wrong endpoint's
        // resources; better to stop.
        let home = TempHome::new("region-conflict");
        let store = home.with_fresh_profile("personal");

        let mut elsewhere = outputs();
        elsewhere.region = Some("eu-west-1".to_string());
        elsewhere.trust_anchor_arn =
            "arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/1111".to_string();
        elsewhere.roles_anywhere_profile_arn =
            "arn:aws:rolesanywhere:eu-west-1:123456789012:profile/2222".to_string();

        let report = sync_profile(&store, "personal", &elsewhere, false).unwrap();
        assert!(report.has_conflicts());
        assert_eq!(report.conflicts().len(), 1);
        assert_eq!(report.conflicts()[0].0, "region");
        assert!(!report.saved, "no field is applied when any conflicts");
    }
}
