//! The TPM key policy.
//!
//! The Windows analogue of `keystone-macos`'s access policy. The Secure Enclave
//! takes an access-control object at creation; CNG takes properties and flags
//! instead, but the decision being made is the same one, and it is made only here.
//!
//! [`KeyAccessibility`] has no CNG equivalent — a TPM key is usable whenever the
//! user's profile is loaded, which is after login, and there is no "while the
//! screen is locked" distinction to draw. Rather than invent a mapping, the policy
//! records the configured value so `inspect` can report what was asked for, and
//! [`TpmPolicy::describe`] says plainly what Windows actually enforces. Silently
//! reporting a guarantee the platform does not make would be worse than saying so.

use keystone_core::config::KeyAccessibility;

/// The policy applied to a Keystone TPM key.
///
/// Constructed only from a [`KeyAccessibility`], mirroring `AccessPolicy`, so
/// there is no way to ask for a Windows Hello-gated key by accident. There is no
/// constructor that enables user presence at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmPolicy {
    accessibility: KeyAccessibility,
}

impl TpmPolicy {
    pub fn new(accessibility: KeyAccessibility) -> Self {
        Self { accessibility }
    }

    pub fn accessibility(self) -> KeyAccessibility {
        self.accessibility
    }

    /// Whether signing with this key can prompt the user.
    ///
    /// Always false: every CNG call passes `NCRYPT_SILENT_FLAG`, so a key that
    /// would prompt fails instead. Present so `doctor` can report the property
    /// rather than asserting it in prose.
    pub fn requires_user_interaction(self) -> bool {
        false
    }

    /// A one-line description for `keystone init` and `keystone inspect`.
    ///
    /// States what Windows enforces, which is not what the configured
    /// accessibility asks for. The configured value is still shown, because a user
    /// who set it should not have to wonder whether it was read.
    pub fn describe(self) -> String {
        let requested = match self.accessibility {
            KeyAccessibility::AfterFirstUnlock => "after first unlock",
            KeyAccessibility::WhenUnlocked => "when unlocked",
        };
        format!(
            "this device only, usable while you are signed in, no user-presence requirement \
             (configured accessibility {requested} has no Windows equivalent and is not enforced)"
        )
    }
}

impl Default for TpmPolicy {
    fn default() -> Self {
        Self::new(KeyAccessibility::default())
    }
}

/// What the TPM reports about this machine, for `keystone doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmReport {
    /// Whether the Platform Crypto Provider opened.
    pub available: bool,
    /// Whether this build can talk to a TPM at all.
    ///
    /// False in a non-Windows build, where the backend is a fail-closed stub.
    pub supported_platform: bool,
    /// A human-readable explanation when `available` is false.
    pub detail: Option<String>,
}

impl TpmReport {
    pub fn unsupported_platform() -> Self {
        Self {
            available: false,
            supported_platform: false,
            detail: Some(
                "this Keystone build does not target Windows, so no TPM is reachable".to_string(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tpm_key_never_requires_user_interaction() {
        // The design forbids adding a user-presence requirement silently, and
        // forbids requiring interaction for each credential refresh. Both
        // accessibilities must answer the same way.
        for accessibility in [
            KeyAccessibility::AfterFirstUnlock,
            KeyAccessibility::WhenUnlocked,
        ] {
            assert!(!TpmPolicy::new(accessibility).requires_user_interaction());
        }
    }

    #[test]
    fn the_description_admits_that_accessibility_is_not_enforced() {
        // Reporting an unenforced guarantee as enforced is the failure this
        // guards: a reader of `keystone inspect` should not believe Windows is
        // honoring a macOS-shaped setting.
        let described = TpmPolicy::new(KeyAccessibility::WhenUnlocked).describe();
        assert!(described.contains("not enforced"), "{described}");
        assert!(
            described.contains("no user-presence requirement"),
            "{described}"
        );
    }

    #[test]
    fn an_unsupported_platform_is_not_reported_as_available() {
        let report = TpmReport::unsupported_platform();
        assert!(!report.available);
        assert!(!report.supported_platform);
        assert!(report.detail.is_some());
    }
}
