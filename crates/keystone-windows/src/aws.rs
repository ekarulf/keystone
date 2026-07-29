//! Binding a TPM key to its certificate for AWS.
//!
//! The exact counterpart of `keystone_macos::aws`, and for the same reason: a key
//! and certificate that do not match produce an AWS rejection whose message names
//! neither, so the mismatch is caught here where it can be described.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use keystone_core::signer::{DerEcdsaSignature, KeystoneSigningIdentity};
use keystone_pki::validate::{validate_device_certificate, ValidationContext};
use keystone_pki::ParsedCertificate;
use keystone_roles_anywhere::AwsX509Identity;
use time::OffsetDateTime;

use crate::tpm::TpmIdentity;

/// A TPM key together with the certificate that names it.
///
/// This is what `keystone credential-process` hands to the Roles Anywhere client
/// on Windows.
#[derive(Debug)]
pub struct CertificateIdentity {
    identity: TpmIdentity,
    certificate: ParsedCertificate,
    /// Intermediates to present, leaf-to-root, excluding the leaf and the anchor.
    ///
    /// Empty for an ephemeral-CA bootstrap, where the issuing CA *is* the trust
    /// anchor and AWS already holds it.
    chain: Vec<Vec<u8>>,
}

impl CertificateIdentity {
    /// Pair a key with its certificate, verifying they belong together.
    ///
    /// Runs the full device-certificate validation — version, end-entity,
    /// `digitalSignature`, validity window, public-key match, and URI SAN — so a
    /// certificate that AWS would reject, or that names another key or device,
    /// fails before any request is built.
    pub fn new(
        identity: TpmIdentity,
        certificate: ParsedCertificate,
        chain: Vec<Vec<u8>>,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let context = ValidationContext::new(now)
            .expecting_key(identity.public_key_sec1()?)
            .expecting_key_id(identity.key_id().clone());
        validate_device_certificate(&certificate, &context)?;

        for (index, der) in chain.iter().enumerate() {
            // Parsing is the check: a chain entry that is not a certificate would
            // otherwise be base64-encoded into a header and rejected remotely.
            ParsedCertificate::from_der(der).map_err(|error| {
                KeystoneError::InvalidCertificateChain(format!(
                    "chain entry {index} is not a usable certificate: {error}"
                ))
            })?;
        }

        Ok(Self {
            identity,
            certificate,
            chain,
        })
    }

    pub fn key_id(&self) -> &KeyId {
        self.identity.key_id()
    }

    pub fn certificate(&self) -> &ParsedCertificate {
        &self.certificate
    }

    pub fn identity(&self) -> &TpmIdentity {
        &self.identity
    }

    /// Confirm the TPM can still sign for this certificate.
    ///
    /// What `keystone doctor` and `keystone test` run before reporting the profile
    /// healthy — it needs no network and no AWS credentials.
    pub fn verify_signing_path(&self, message: &[u8]) -> Result<()> {
        let signature = self.identity.sign_message_ecdsa_sha256(message)?;
        keystone_pki::ephemeral_ca::verify_device_signature(&self.certificate, message, &signature)
    }
}

impl AwsX509Identity for CertificateIdentity {
    fn certificate_serial_decimal(&self) -> Result<String> {
        Ok(self.certificate.serial_decimal.clone())
    }

    fn leaf_certificate_der(&self) -> &[u8] {
        self.certificate.der()
    }

    fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.chain
    }

    /// Sign the Roles Anywhere string-to-sign.
    ///
    /// The string-to-sign is passed as a *message*, exactly as on macOS, and the
    /// backend hashes it once. That the hash happens in Keystone here rather than
    /// inside CryptoKit is invisible at this seam, which is the point of routing
    /// through `sign_message_ecdsa_sha256` instead of reaching for the TPM's
    /// native prehashed operation: this function would then have to hash, and a
    /// future edit could easily leave both hashes in place.
    fn sign_string_to_sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>> {
        self.identity
            .sign_message_ecdsa_sha256(string_to_sign)
            .map(DerEcdsaSignature::into_bytes)
    }
}

/// These need a real TPM, so they are compiled only where one can exist.
///
/// Mirrors the macOS suite case for case. The certificate half of the pairing is
/// also covered without hardware by `keystone-pki`'s validation tests, and the
/// signing half by `keystone-roles-anywhere`'s software test identity.
#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::access::TpmPolicy;
    use crate::tpm::{self, TpmIdentity};
    use keystone_core::identity::{IdentityMetadata, KeyType};
    use keystone_pki::params::{DeviceCertificateSpec, EphemeralCaSpec};

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    /// A generated key that deletes itself when the test ends.
    ///
    /// CNG keys persist beyond the process, unlike a Secure Enclave key held only
    /// by its blob. Without this, every test run would leave a TPM key behind, and
    /// the TPM has finite storage.
    struct TempKey(Option<TpmIdentity>);

    impl Drop for TempKey {
        fn drop(&mut self) {
            if let Some(identity) = self.0.take() {
                let _ = identity.delete_key();
            }
        }
    }

    /// The metadata that `generate` would have written for this identity.
    ///
    /// Lets a test reopen a key it has handed away — the pairing constructor
    /// consumes the identity, and a failed pairing drops it without deleting the
    /// TPM key.
    fn metadata_for(identity: &TpmIdentity) -> IdentityMetadata {
        IdentityMetadata::with_key_type(
            identity.key_id().clone(),
            KeyType::WindowsTpmP256Signing,
            &identity.public_key_sec1().unwrap(),
            tpm::key_name_for(identity.key_id()).as_bytes(),
            NOW,
        )
    }

    /// Generate a key and issue it a certificate through the ephemeral CA.
    ///
    /// Returns `None` when this machine has no usable TPM.
    fn bootstrap() -> Option<(CertificateIdentity, ParsedCertificate)> {
        if !tpm::is_available().expect("querying the TPM") {
            return None;
        }
        let key_id = KeyId::generate();
        let generated = TpmIdentity::generate(key_id.clone(), TpmPolicy::default(), NOW).unwrap();

        let device = DeviceCertificateSpec::new("erik-pc", key_id.clone(), NOW);
        let ca = EphemeralCaSpec::new(key_id, NOW);
        let output = keystone_pki::ephemeral_ca::issue(
            &generated.identity.public_key_sec1().unwrap(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();

        let anchor = output.ca_certificate.clone();
        let chain = output.chain_der();
        let identity =
            CertificateIdentity::new(generated.identity, output.device_certificate, chain, NOW)
                .unwrap();
        Some((identity, anchor))
    }

    #[test]
    fn a_bootstrapped_identity_can_sign_for_its_own_certificate() {
        // The end-to-end property: the key that never left the TPM is the key the
        // certificate names, and the chain terminates at the CA.
        let Some((identity, anchor)) = bootstrap() else {
            return;
        };
        identity
            .verify_signing_path(b"AWS4-X509-ECDSA-SHA256\n20260726T011500Z\nscope\ndigest")
            .unwrap();
        keystone_pki::validate_chain(identity.certificate(), &[], &anchor, NOW).unwrap();
        let _cleanup = TempKey(Some(identity.identity));
    }

    #[test]
    fn the_serial_number_is_reported_in_decimal_for_the_credential_field() {
        let Some((identity, _)) = bootstrap() else {
            return;
        };
        let serial = identity.certificate_serial_decimal().unwrap();
        assert!(
            serial.chars().all(|c| c.is_ascii_digit()),
            "serial {serial} is not decimal"
        );
        assert!(!serial.is_empty());
        let _cleanup = TempKey(Some(identity.identity));
    }

    #[test]
    fn no_intermediates_are_presented_for_an_ephemeral_ca_bootstrap() {
        // The CA is the trust anchor, which AWS already holds.
        let Some((identity, _)) = bootstrap() else {
            return;
        };
        assert!(identity.certificate_chain_der().is_empty());
        assert_eq!(
            identity.leaf_certificate_der(),
            identity.certificate().der()
        );
        let _cleanup = TempKey(Some(identity.identity));
    }

    #[test]
    fn the_string_to_sign_is_hashed_exactly_once() {
        // The design's explicit warning: "Do not accidentally hash the Roles
        // Anywhere string-to-sign twice." This matters more on Windows than on
        // macOS, because CNG signs a digest and the hash is Keystone's to apply.
        // If it were applied twice, verification against the raw string-to-sign
        // fails here rather than as an opaque AWS rejection.
        let Some((identity, _)) = bootstrap() else {
            return;
        };
        let string_to_sign = b"AWS4-X509-ECDSA-SHA256\n20260726T011500Z\n\
                              20260726/us-east-1/rolesanywhere/aws4_request\nabc123";
        let signature = identity.sign_string_to_sign(string_to_sign).unwrap();
        keystone_pki::verify_der_signature(
            &identity.identity().public_key_sec1().unwrap(),
            string_to_sign,
            &signature,
        )
        .unwrap();
        let _cleanup = TempKey(Some(identity.identity));
    }

    #[test]
    fn the_prehashed_and_message_signers_agree() {
        // Windows-specific: both traits reach the same CNG operation, and the
        // wrapper's only job is the hash. A digest signed directly must verify
        // against the message it is the digest of.
        use keystone_core::signer::PrehashedSigner as _;
        use sha2::{Digest as _, Sha256};

        let Some((identity, _)) = bootstrap() else {
            return;
        };
        let message = b"a string to sign";
        let digest: [u8; 32] = Sha256::digest(message).into();
        let signature = identity
            .identity()
            .sign_prehashed_sha256(&digest)
            .unwrap()
            .into_bytes();
        keystone_pki::verify_der_signature(
            &identity.identity().public_key_sec1().unwrap(),
            message,
            &signature,
        )
        .unwrap();
        let _cleanup = TempKey(Some(identity.identity));
    }

    #[test]
    fn a_restored_identity_signs_identically_to_the_generated_one() {
        // The name-not-blob difference from macOS: the whole restore path is
        // `open` plus a public-key comparison, so it deserves a live test that the
        // reopened handle is the same key.
        if !tpm::is_available().expect("querying the TPM") {
            return;
        }
        let generated =
            TpmIdentity::generate(KeyId::generate(), TpmPolicy::default(), NOW).unwrap();
        let public_key = generated.identity.public_key_sec1().unwrap();
        let metadata = generated.metadata.clone();
        drop(generated.identity);

        let restored = TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap();
        assert_eq!(restored.public_key_sec1().unwrap(), public_key);
        restored.self_test().unwrap();
        let _cleanup = TempKey(Some(restored));
    }

    #[test]
    fn restoring_an_identity_whose_public_key_does_not_match_is_refused() {
        // The check that makes a stored *name* safe. Simulated by rewriting the
        // recorded public key, which is what a swapped identity file looks like.
        if !tpm::is_available().expect("querying the TPM") {
            return;
        }
        let generated =
            TpmIdentity::generate(KeyId::generate(), TpmPolicy::default(), NOW).unwrap();
        let recorded = generated.metadata.clone();
        let _cleanup = TempKey(Some(generated.identity));

        // A different, well-formed point, with a fingerprint that matches it: the
        // metadata must be internally consistent so the failure is the public-key
        // comparison and not `validate()`'s fingerprint check.
        let mut other = [0u8; 65];
        other[0] = 0x04;
        other[1] = 0x07;
        let metadata = IdentityMetadata::with_key_type(
            recorded.key_id.clone(),
            recorded.key_type,
            &other,
            &recorded.opaque_key_reference_bytes().unwrap(),
            recorded.created_at,
        );

        let error = TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("may have been replaced"), "{message}");
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        if !tpm::is_available().expect("querying the TPM") {
            return;
        }

        // Two keys, and the certificate issued to the first handed to the second.
        let first = TpmIdentity::generate(KeyId::generate(), TpmPolicy::default(), NOW).unwrap();
        let second_key_id = KeyId::generate();
        let second =
            TpmIdentity::generate(second_key_id.clone(), TpmPolicy::default(), NOW).unwrap();

        let device = DeviceCertificateSpec::new("erik-pc", second_key_id.clone(), NOW);
        let ca = EphemeralCaSpec::new(second_key_id, NOW);
        let output = keystone_pki::ephemeral_ca::issue(
            &second.identity.public_key_sec1().unwrap(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();
        let _cleanup_second = TempKey(Some(second.identity));

        // Both TPM keys outlive the failed pairing, which consumes the identity
        // handle without deleting anything, so `first` is reopened to clean up.
        let first_metadata = metadata_for(&first.identity);
        let error =
            CertificateIdentity::new(first.identity, output.device_certificate, Vec::new(), NOW)
                .unwrap_err();
        assert!(
            matches!(error, KeystoneError::CertificateKeyMismatch),
            "{error}"
        );
        let _cleanup_first = TempKey(Some(
            TpmIdentity::restore(&first_metadata, TpmPolicy::default()).unwrap(),
        ));
    }

    #[test]
    fn an_expired_certificate_is_refused_at_construction() {
        // Better than discovering it in an AWS error, which does not say what
        // expired.
        let Some((paired, _)) = bootstrap() else {
            return;
        };
        let expired = paired.certificate().not_after + time::Duration::days(1);
        let metadata = metadata_for(paired.identity());
        let certificate = paired.certificate().clone();
        drop(paired);

        let identity = TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap();
        let error =
            CertificateIdentity::new(identity, certificate, Vec::new(), expired).unwrap_err();
        assert!(
            matches!(error, KeystoneError::CertificateExpired(_)),
            "{error}"
        );
        let _cleanup = TempKey(Some(
            TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap(),
        ));
    }

    #[test]
    fn a_junk_chain_entry_is_refused_before_it_reaches_a_header() {
        let Some((paired, _)) = bootstrap() else {
            return;
        };
        let metadata = metadata_for(paired.identity());
        let certificate = paired.certificate().clone();
        drop(paired);

        let identity = TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap();
        let error = CertificateIdentity::new(
            identity,
            certificate,
            vec![b"not a certificate".to_vec()],
            NOW,
        )
        .unwrap_err();
        assert!(
            matches!(error, KeystoneError::InvalidCertificateChain(_)),
            "{error}"
        );
        let _cleanup = TempKey(Some(
            TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap(),
        ));
    }
}
