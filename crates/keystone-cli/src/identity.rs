//! Restoring the device identity a profile names.
//!
//! Every command that signs anything goes through [`load_identity`], so the
//! checks happen in exactly one place: the hardware key store must be present,
//! the key must restore, the stored certificate must belong to that key, and the
//! certificate must still be valid. If any of those fails, Keystone fails —
//! there is no software fallback.
//!
//! Which key store that is — the Secure Enclave or the TPM — is [`crate::backend`]'s
//! decision, not this module's.

use crate::backend::{CertificateIdentity, DeviceKey, KeyPolicy};
use keystone_core::config::Profile;
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::Sha256Fingerprint;
use keystone_core::store::Store;
use keystone_pki::ParsedCertificate;
use time::OffsetDateTime;

/// The device identity plus the public certificates it was loaded from.
pub struct LoadedIdentity {
    pub identity: CertificateIdentity,
    pub certificate: ParsedCertificate,
    pub ca_certificate: ParsedCertificate,
}

/// Restore the hardware key a profile names, without its certificate.
///
/// `keystone enroll csr` needs this: at that point there is no certificate yet.
pub fn load_key(store: &Store, profile_name: &str, profile: &Profile) -> Result<DeviceKey> {
    let key_id = profile
        .key_id
        .clone()
        .ok_or_else(|| KeystoneError::ProfileIncomplete {
            profile: profile_name.to_string(),
            reason: format!(
                "no {} identity. Run `keystone init` or `keystone bootstrap` first.",
                crate::backend::KEY_STORE
            ),
        })?;
    let metadata = store.load_identity(&key_id)?;
    DeviceKey::restore(&metadata, KeyPolicy::new(profile.key_accessibility))
}

/// Restore the key and pair it with the stored certificate.
///
/// The pairing runs the full device-certificate validation, so a certificate
/// installed for a different key — or one that has expired — is refused here
/// rather than by AWS.
pub fn load_identity(
    store: &Store,
    profile_name: &str,
    profile: &Profile,
    now: OffsetDateTime,
) -> Result<LoadedIdentity> {
    let key = load_key(store, profile_name, profile)?;

    let fingerprint = profile
        .certificate_fingerprint_sha256
        .clone()
        .ok_or_else(|| KeystoneError::ProfileIncomplete {
            profile: profile_name.to_string(),
            reason:
                "no device certificate. Run `keystone bootstrap`, or `keystone enroll install` \
                     with a certificate from your CA."
                    .to_string(),
        })?;

    let (leaf_der, ca_der) = store.load_certificates(&fingerprint)?;
    let certificate = ParsedCertificate::from_der(&leaf_der)?;
    let ca_certificate = ParsedCertificate::from_der(&ca_der)?;

    // The recorded fingerprint must match the file's actual content: otherwise a
    // swapped certificate file would be used under the name of the one the
    // profile approved.
    let actual = certificate.fingerprint();
    if actual != fingerprint {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "the stored certificate has fingerprint {} but profile {profile_name} records {}. \
             Re-run enrollment.",
            actual.display_short(),
            fingerprint.display_short()
        )));
    }
    check_recorded_ca_fingerprint(profile, profile_name, &ca_certificate)?;

    // The chain sent to AWS excludes the anchor, and for an ephemeral CA the
    // issuing CA *is* the anchor, so there are no intermediates to present.
    let identity = CertificateIdentity::new(key, certificate.clone(), Vec::new(), now)?;

    Ok(LoadedIdentity {
        identity,
        certificate,
        ca_certificate,
    })
}

/// Confirm the stored CA is the one the profile recorded.
fn check_recorded_ca_fingerprint(
    profile: &Profile,
    profile_name: &str,
    ca_certificate: &ParsedCertificate,
) -> Result<()> {
    let Some(expected) = &profile.ca_fingerprint_sha256 else {
        return Ok(());
    };
    let actual: Sha256Fingerprint = ca_certificate.fingerprint();
    if actual != *expected {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "the stored CA certificate has fingerprint {} but profile {profile_name} records {}. \
             The trust anchor deployed in AWS holds the recorded CA, so this chain would be \
             rejected.",
            actual.display_short(),
            expected.display_short()
        )));
    }
    Ok(())
}
