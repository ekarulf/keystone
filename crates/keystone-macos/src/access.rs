//! The Secure Enclave access policy.
//!
//! The design's recommended default is:
//!
//! ```text
//! private-key usage
//! after first unlock
//! this device only
//! no user-presence requirement
//! ```
//!
//! and states that "Keystone must not silently add biometric or user-presence
//! requirements". This module is the only place that decides what a key's access
//! control is, and [`AccessPolicy::requires_user_interaction`] lets the CLI state
//! the policy in `keystone init` and `keystone doctor` output.
//!
//! The policy is deliberately not configurable beyond `key_accessibility`. An
//! interaction-requiring key is a different product decision — the design defers
//! it to "higher-privilege profiles" — not a flag to be threaded through here.

use keystone_core::config::KeyAccessibility;

/// The access-control policy applied to a Keystone Secure Enclave key.
///
/// Constructed only from a [`KeyAccessibility`], so there is no way to ask for a
/// biometric or passcode-gated key by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessPolicy {
    accessibility: KeyAccessibility,
}

impl AccessPolicy {
    /// The policy for a profile's configured accessibility.
    pub fn new(accessibility: KeyAccessibility) -> Self {
        Self { accessibility }
    }

    pub fn accessibility(self) -> KeyAccessibility {
        self.accessibility
    }

    /// Whether signing with this key can prompt the user.
    ///
    /// Always false. The method exists so `doctor` can report the property rather
    /// than asserting it in prose, and so a future interaction-requiring policy
    /// has an obvious place to change this answer.
    pub fn requires_user_interaction(self) -> bool {
        false
    }

    /// A one-line description for `keystone init` and `keystone inspect`.
    pub fn describe(self) -> String {
        let when = match self.accessibility {
            KeyAccessibility::AfterFirstUnlock => {
                "usable after the first login following boot, including while the screen is locked"
            }
            KeyAccessibility::WhenUnlocked => "usable only while the Mac is unlocked",
        };
        format!("this device only, {when}, no user-presence requirement")
    }
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self::new(KeyAccessibility::default())
    }
}

/// What the Secure Enclave reports about this machine, for `keystone doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveReport {
    /// Whether CryptoKit reports a usable Secure Enclave.
    pub available: bool,
    /// Whether this build can talk to a Secure Enclave at all.
    ///
    /// False in a non-macOS build, where the backend is a fail-closed stub.
    pub supported_platform: bool,
    /// A human-readable explanation when `available` is false.
    pub detail: Option<String>,
}

impl EnclaveReport {
    pub fn unsupported_platform() -> Self {
        Self {
            available: false,
            supported_platform: false,
            detail: Some(
                "this Keystone build does not target macOS, so no Secure Enclave is reachable"
                    .to_string(),
            ),
        }
    }
}

#[cfg(target_os = "macos")]
mod cryptokit_mapping {
    use super::AccessPolicy;
    use cryptokit::secure_enclave::{
        SecureEnclaveAccessControl, SecureEnclaveAccessControlFlags, SecureEnclaveAccessibility,
    };
    use keystone_core::config::KeyAccessibility;

    impl AccessPolicy {
        /// The CryptoKit access control for this policy.
        ///
        /// The `ThisDeviceOnly` variants keep the key out of Keychain sync, and the
        /// flag set is always empty: any of `USER_PRESENCE`, `BIOMETRY_ANY`,
        /// `BIOMETRY_CURRENT_SET`, or `DEVICE_PASSCODE` would make every credential
        /// refresh raise a prompt, which the design forbids.
        ///
        /// `PRIVATE_KEY_USAGE` is not set here either: CryptoKit's
        /// `SecureEnclave.P256.Signing.PrivateKey` already constrains the key to
        /// signing, and passing the flag without a paired constraint flag is
        /// rejected by `SecAccessControlCreateWithFlags` on some releases.
        pub(crate) fn to_cryptokit(self) -> SecureEnclaveAccessControl {
            let accessibility = match self.accessibility() {
                KeyAccessibility::AfterFirstUnlock => {
                    SecureEnclaveAccessibility::AfterFirstUnlockThisDeviceOnly
                }
                KeyAccessibility::WhenUnlocked => {
                    SecureEnclaveAccessibility::WhenUnlockedThisDeviceOnly
                }
            };
            SecureEnclaveAccessControl::new(accessibility, SecureEnclaveAccessControlFlags::empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_is_the_unattended_one() {
        // Credential refresh has to work for background agents, so a key that
        // stops working when the screen locks cannot be the default.
        assert_eq!(
            AccessPolicy::default().accessibility(),
            KeyAccessibility::AfterFirstUnlock
        );
    }

    #[test]
    fn no_policy_requires_user_interaction() {
        for accessibility in [
            KeyAccessibility::AfterFirstUnlock,
            KeyAccessibility::WhenUnlocked,
        ] {
            let policy = AccessPolicy::new(accessibility);
            assert!(
                !policy.requires_user_interaction(),
                "{accessibility:?} must not prompt"
            );
            assert!(
                policy.describe().contains("no user-presence requirement"),
                "{}",
                policy.describe()
            );
        }
    }

    #[test]
    fn the_description_distinguishes_the_two_accessibilities() {
        // The difference matters operationally — one survives a locked screen —
        // so `init` output must not describe both the same way.
        let after_first_unlock = AccessPolicy::new(KeyAccessibility::AfterFirstUnlock).describe();
        let when_unlocked = AccessPolicy::new(KeyAccessibility::WhenUnlocked).describe();
        assert_ne!(after_first_unlock, when_unlocked);
        assert!(
            after_first_unlock.contains("locked"),
            "{after_first_unlock}"
        );
        assert!(when_unlocked.contains("unlocked"), "{when_unlocked}");
        for description in [&after_first_unlock, &when_unlocked] {
            assert!(description.contains("this device only"), "{description}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_cryptokit_policy_carries_no_interaction_flags() {
        use cryptokit::secure_enclave::{
            SecureEnclaveAccessControlFlags as Flags, SecureEnclaveAccessibility,
        };

        // The check that keeps a Touch ID prompt out of `credential-process`.
        let forbidden = [
            ("USER_PRESENCE", Flags::USER_PRESENCE),
            ("BIOMETRY_ANY", Flags::BIOMETRY_ANY),
            ("BIOMETRY_CURRENT_SET", Flags::BIOMETRY_CURRENT_SET),
            ("DEVICE_PASSCODE", Flags::DEVICE_PASSCODE),
            ("COMPANION", Flags::COMPANION),
        ];
        for accessibility in [
            KeyAccessibility::AfterFirstUnlock,
            KeyAccessibility::WhenUnlocked,
        ] {
            let control = AccessPolicy::new(accessibility).to_cryptokit();
            assert_eq!(
                control.flags().bits(),
                Flags::empty().bits(),
                "{accessibility:?} must request no access-control flags"
            );
            for (name, flag) in forbidden {
                assert_eq!(
                    control.flags().bits() & flag.bits(),
                    0,
                    "{accessibility:?} must not set {name}"
                );
            }
        }

        // And the key must stay on this device: a synced key would be a copy of
        // an identity that is supposed to be hardware-bound.
        assert_eq!(
            AccessPolicy::new(KeyAccessibility::AfterFirstUnlock)
                .to_cryptokit()
                .accessibility(),
            SecureEnclaveAccessibility::AfterFirstUnlockThisDeviceOnly
        );
        assert_eq!(
            AccessPolicy::new(KeyAccessibility::WhenUnlocked)
                .to_cryptokit()
                .accessibility(),
            SecureEnclaveAccessibility::WhenUnlockedThisDeviceOnly
        );
    }
}
