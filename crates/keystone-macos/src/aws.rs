//! Binding a Secure Enclave key to its certificate for AWS.
//!
//! [`CertificateIdentity`] pairs a [`SecureEnclaveIdentity`] with the certificate
//! AWS should see, and implements
//! [`AwsX509Identity`](keystone_roles_anywhere::AwsX509Identity) over the two.
//!
//! The pairing is checked at construction, not at signing time. A key and
//! certificate that do not match produce an AWS rejection whose message names
//! neither, so the mismatch is caught here where it can be described.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use keystone_core::signer::{DerEcdsaSignature, KeystoneSigningIdentity};
use keystone_pki::validate::{validate_device_certificate, ValidationContext};
use keystone_pki::ParsedCertificate;
use keystone_roles_anywhere::AwsX509Identity;
use time::OffsetDateTime;

use crate::enclave::SecureEnclaveIdentity;

/// A Secure Enclave key together with the certificate that names it.
///
/// This is what `keystone credential-process` hands to the Roles Anywhere client.
#[derive(Debug)]
pub struct CertificateIdentity {
    identity: SecureEnclaveIdentity,
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
        identity: SecureEnclaveIdentity,
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

    pub fn identity(&self) -> &SecureEnclaveIdentity {
        &self.identity
    }

    /// Confirm the enclave can still sign for this certificate.
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
    /// The string-to-sign is passed as a *message*: SHA-256 is applied once, by
    /// CryptoKit. This matches the official helper's
    /// `Sign(rand, stringToSign, crypto.SHA256)`. Hashing here first would hash
    /// twice.
    fn sign_string_to_sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>> {
        self.identity
            .sign_message_ecdsa_sha256(string_to_sign)
            .map(DerEcdsaSignature::into_bytes)
    }
}

/// These need a real key, so they are compiled only where one can exist.
///
/// The certificate half of the pairing is covered without hardware by
/// `keystone-pki`'s validation tests, and the signing half by
/// `keystone-roles-anywhere`'s software test identity.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::access::AccessPolicy;
    use crate::enclave::{self, SecureEnclaveIdentity};
    use keystone_pki::params::{DeviceCertificateSpec, EphemeralCaSpec};

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    /// Generate a key and issue it a certificate through the ephemeral CA.
    ///
    /// Returns `None` when this machine has no Secure Enclave.
    fn bootstrap() -> Option<(CertificateIdentity, ParsedCertificate)> {
        if !enclave::is_available().expect("querying the Secure Enclave") {
            return None;
        }
        let key_id = KeyId::generate();
        let generated =
            SecureEnclaveIdentity::generate(key_id.clone(), AccessPolicy::default(), NOW).unwrap();

        let device = DeviceCertificateSpec::new("erik-macbook", key_id.clone(), NOW);
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
        // The end-to-end property: the key that never left the enclave is the key
        // the certificate names, and the chain terminates at the CA.
        let Some((identity, anchor)) = bootstrap() else {
            return;
        };
        identity
            .verify_signing_path(b"AWS4-X509-ECDSA-SHA256\n20260726T011500Z\nscope\ndigest")
            .unwrap();
        keystone_pki::validate_chain(identity.certificate(), &[], &anchor, NOW).unwrap();
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
    }

    #[test]
    fn the_string_to_sign_is_hashed_exactly_once() {
        // The design's explicit warning: "Do not accidentally hash the Roles
        // Anywhere string-to-sign twice."
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
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let Some((_, _)) = bootstrap() else { return };

        // Two keys, and the certificate issued to the first handed to the second.
        let first =
            SecureEnclaveIdentity::generate(KeyId::generate(), AccessPolicy::default(), NOW)
                .unwrap();
        let second_key_id = KeyId::generate();
        let second =
            SecureEnclaveIdentity::generate(second_key_id.clone(), AccessPolicy::default(), NOW)
                .unwrap();

        let device = DeviceCertificateSpec::new("erik-macbook", second_key_id.clone(), NOW);
        let ca = EphemeralCaSpec::new(second_key_id, NOW);
        let output = keystone_pki::ephemeral_ca::issue(
            &second.identity.public_key_sec1().unwrap(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();

        let error =
            CertificateIdentity::new(first.identity, output.device_certificate, Vec::new(), NOW)
                .unwrap_err();
        assert!(
            matches!(error, KeystoneError::CertificateKeyMismatch),
            "{error}"
        );
    }

    #[test]
    fn an_expired_certificate_is_refused_at_construction() {
        // Better than discovering it in an AWS error, which does not say what
        // expired.
        let Some((identity, _)) = bootstrap() else {
            return;
        };
        let expired = identity.certificate().not_after + time::Duration::days(1);
        let error =
            CertificateIdentity::new(identity.identity, identity.certificate, Vec::new(), expired)
                .unwrap_err();
        assert!(
            matches!(error, KeystoneError::CertificateExpired(_)),
            "{error}"
        );
    }

    #[test]
    fn a_junk_chain_entry_is_refused_before_it_reaches_a_header() {
        let Some((identity, _)) = bootstrap() else {
            return;
        };
        let error = CertificateIdentity::new(
            identity.identity,
            identity.certificate,
            vec![b"not a certificate".to_vec()],
            NOW,
        )
        .unwrap_err();
        assert!(
            matches!(error, KeystoneError::InvalidCertificateChain(_)),
            "{error}"
        );
    }
}
