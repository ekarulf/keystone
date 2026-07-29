//! The one-shot software CA.
//!
//! The CA key exists only inside this module's `issue` call: it is generated,
//! used to sign a self-signed CA certificate and exactly one device
//! certificate, then dropped. Nothing here returns, serializes, or accepts a CA
//! private key, so no caller can persist one — the design's "the CA key must not
//! be written to the ordinary filesystem" is enforced by the API shape rather
//! than by convention.
//!
//! Dropping is not erasure. The private scalar lives inside *ring*, which exposes
//! no way to scrub it, so it remains in freed process memory until that memory is
//! reused; see [`EphemeralCaKey`] for what that does and does not leave exposed.
//! Unreachability plus a short-lived process is the mitigation, not a guarantee.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::Sha256Fingerprint;
use keystone_core::signer::DerEcdsaSignature;
use rcgen::{Issuer, KeyPair, PublicKeyData, SignatureAlgorithm};
use time::OffsetDateTime;

use crate::certificate::ParsedCertificate;
use crate::params::{DeviceCertificateSpec, EphemeralCaSpec};
use crate::validate::{self, ValidationContext};

/// The public artifacts of a bootstrap. There is deliberately no field for the
/// CA private key.
#[derive(Debug, Clone)]
pub struct EphemeralCaOutput {
    /// The self-signed CA certificate, to register as the trust anchor.
    pub ca_certificate: ParsedCertificate,
    /// The device certificate for the Secure Enclave key.
    pub device_certificate: ParsedCertificate,
}

impl EphemeralCaOutput {
    pub fn ca_fingerprint(&self) -> Sha256Fingerprint {
        self.ca_certificate.fingerprint()
    }

    pub fn device_fingerprint(&self) -> Sha256Fingerprint {
        self.device_certificate.fingerprint()
    }

    /// The chain to send in `x-amz-x509-chain`.
    ///
    /// Empty: the CA is itself the trust anchor, and AWS already has it, so
    /// there are no intermediates to present.
    pub fn chain_der(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// The PEM bundle written as `device-chain.pem`, leaf first.
    pub fn chain_pem(&self) -> String {
        format!(
            "{}{}",
            self.device_certificate.to_pem(),
            self.ca_certificate.to_pem()
        )
    }
}

/// The public key of the device the certificate is issued to.
///
/// Wraps the SEC1 bytes so rcgen can name the key in a certificate without
/// having a private key for it: the Secure Enclave signs nothing during
/// issuance, since the CA signs the device certificate.
struct DevicePublicKey {
    sec1: Vec<u8>,
}

impl PublicKeyData for DevicePublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.sec1
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

/// A CA key that exists only for the duration of one `issue` call.
///
/// What this guarantees, and what it does not, because the difference matters for
/// the claim that an ephemeral CA "can never sign again":
///
/// * guaranteed — the key never reaches disk, a log, or the network, and it is
///   unreachable through any API once [`issue`] returns. There is no accessor and
///   no serialization path; `EphemeralCaOutput` carries only certificates.
/// * not guaranteed — the private scalar is not scrubbed from process memory.
///   `rcgen::KeyPair` holds it inside *ring*, which exposes no way to zeroize it,
///   and rcgen's own PKCS#8 buffer is not writable from here either.
///
/// So the residual exposure is a core dump, an attached debugger, or swapped-out
/// pages during the seconds a bootstrap runs. Closing it properly needs a
/// zeroize-aware key type rather than a `Drop` impl that cannot reach the bytes;
/// an earlier version of this `Drop` zeroed a `to_vec()` copy, which achieved
/// nothing but looked like it had.
struct EphemeralCaKey {
    key_pair: KeyPair,
}

impl EphemeralCaKey {
    fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| KeystoneError::Other(format!("cannot generate CA key: {e}")))?;
        Ok(Self { key_pair })
    }
}

// No `Drop` impl. There is nothing here it could usefully wipe: see the note on
// `EphemeralCaKey`. A `Drop` that zeroed a copy of the serialized key would leave
// the original untouched while reading as though the key had been erased, which is
// worse than being explicit about the limitation.

/// Generate a one-shot CA and issue one device certificate with it.
///
/// The CA key is dropped before this function returns; there is no way to obtain
/// it. Both certificates are validated before being returned, so a bootstrap
/// that produced something Keystone would later reject fails now, while the
/// state is still discardable.
pub fn issue(
    device_public_key_sec1: &[u8; 65],
    device: &DeviceCertificateSpec,
    ca: &EphemeralCaSpec,
    now: OffsetDateTime,
) -> Result<EphemeralCaOutput> {
    if ca.not_after < device.not_after {
        return Err(KeystoneError::InvalidConfiguration(
            "the ephemeral CA must remain valid at least as long as the device certificate"
                .to_string(),
        ));
    }

    let ca_params = ca.to_params()?;
    let device_params = device.to_params()?;

    let ca_certificate_der = {
        let ca_key = EphemeralCaKey::generate()?;

        let ca_certificate = ca_params
            .self_signed(&ca_key.key_pair)
            .map_err(|e| KeystoneError::Other(format!("cannot create CA certificate: {e}")))?;

        let issuer = Issuer::from_params(&ca_params, &ca_key.key_pair);
        let device_certificate = device_params
            .signed_by(
                &DevicePublicKey {
                    sec1: device_public_key_sec1.to_vec(),
                },
                &issuer,
            )
            .map_err(|e| {
                KeystoneError::Other(format!("cannot sign the device certificate: {e}"))
            })?;

        // The CA key is dropped at the end of this block, before anything is
        // returned to the caller, which is what makes it unreachable. It is not
        // scrubbed — see `EphemeralCaKey`.
        (
            ca_certificate.der().to_vec(),
            device_certificate.der().to_vec(),
        )
    };
    let (ca_der, device_der) = ca_certificate_der;

    let ca_certificate = ParsedCertificate::from_der(&ca_der)?;
    let device_certificate = ParsedCertificate::from_der(&device_der)?;

    // Verify what was just built, rather than trusting the builder: a
    // certificate Keystone would reject at credential time must fail here.
    validate::validate_ca_certificate(&ca_certificate, now)?;
    validate::validate_device_certificate(
        &device_certificate,
        &ValidationContext {
            now,
            expected_public_key_sec1: Some(*device_public_key_sec1),
            expected_key_id: Some(device.key_id.clone()),
        },
    )?;
    validate::validate_chain(&device_certificate, &[], &ca_certificate, now)?;

    Ok(EphemeralCaOutput {
        ca_certificate,
        device_certificate,
    })
}

/// Verify a signature that a device made, using the certificate's public key.
///
/// Used by `keystone doctor` to confirm the Secure Enclave key still matches the
/// installed certificate without contacting AWS.
pub fn verify_device_signature(
    certificate: &ParsedCertificate,
    message: &[u8],
    signature: &DerEcdsaSignature,
) -> Result<()> {
    use p256::ecdsa::signature::Verifier as _;

    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&certificate.public_key_sec1)
        .map_err(|e| {
            KeystoneError::InvalidCertificate(format!("certificate public key is unusable: {e}"))
        })?;
    let parsed = p256::ecdsa::Signature::from_der(signature.as_bytes())
        .map_err(|e| KeystoneError::Other(format!("signature is not valid DER ECDSA: {e}")))?;
    verifying_key
        .verify(message, &parsed)
        .map_err(|_| KeystoneError::CertificateKeyMismatch)
}

/// The full signing key of an issued identity, for tests only.
#[cfg(any(test, feature = "testing"))]
pub use crate::testing::TestCa;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;
    use keystone_core::identity::KeyId;

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn specs(key_id: &KeyId) -> (DeviceCertificateSpec, EphemeralCaSpec) {
        (
            DeviceCertificateSpec::new("example-laptop", key_id.clone(), NOW),
            EphemeralCaSpec::new(key_id.clone(), NOW),
        )
    }

    #[test]
    fn a_bootstrap_produces_a_ca_and_a_matching_device_certificate() {
        let key_id = KeyId::generate();
        let device_key = testing::random_device_key();
        let (device, ca) = specs(&key_id);

        let output = issue(&device_key.public_key_sec1(), &device, &ca, NOW).unwrap();

        assert!(output.ca_certificate.is_ca);
        assert!(!output.device_certificate.is_ca);
        assert_eq!(
            output.device_certificate.public_key_sec1,
            device_key.public_key_sec1()
        );
        assert_eq!(
            output.device_certificate.device_key_id().as_ref(),
            Some(&key_id)
        );
        assert_eq!(
            output.device_certificate.issuer,
            output.ca_certificate.subject
        );
    }

    #[test]
    fn the_device_certificate_verifies_against_the_ca() {
        let key_id = KeyId::generate();
        let device_key = testing::random_device_key();
        let (device, ca) = specs(&key_id);
        let output = issue(&device_key.public_key_sec1(), &device, &ca, NOW).unwrap();

        validate::validate_chain(&output.device_certificate, &[], &output.ca_certificate, NOW)
            .unwrap();
    }

    #[test]
    fn the_secure_enclave_key_can_sign_for_the_issued_certificate() {
        // The end-to-end property the whole bootstrap exists for: the key that
        // never left the device is the key the certificate names.
        let key_id = KeyId::generate();
        let device_key = testing::random_device_key();
        let (device, ca) = specs(&key_id);
        let output = issue(&device_key.public_key_sec1(), &device, &ca, NOW).unwrap();

        let message = b"AWS4-X509-ECDSA-SHA256\n20260726T011500Z\n...";
        let signature = device_key.sign_der(message);
        verify_device_signature(&output.device_certificate, message, &signature).unwrap();

        // And a signature over different bytes does not verify.
        assert!(
            verify_device_signature(&output.device_certificate, b"other bytes", &signature)
                .is_err()
        );
    }

    #[test]
    fn a_different_key_cannot_sign_for_the_certificate() {
        let key_id = KeyId::generate();
        let device_key = testing::random_device_key();
        let (device, ca) = specs(&key_id);
        let output = issue(&device_key.public_key_sec1(), &device, &ca, NOW).unwrap();

        let impostor = testing::random_device_key();
        let signature = impostor.sign_der(b"message");
        assert!(matches!(
            verify_device_signature(&output.device_certificate, b"message", &signature),
            Err(KeystoneError::CertificateKeyMismatch)
        ));
    }

    #[test]
    fn the_issued_certificate_cannot_sign_other_certificates() {
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        let output = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();

        assert!(!output.device_certificate.is_ca);
        assert!(output.device_certificate.basic_constraints_critical);
        assert!(!output.device_certificate.key_usage_key_cert_sign);
    }

    #[test]
    fn a_ca_that_expires_before_the_device_certificate_is_refused() {
        // The chain would stop validating while the leaf still looked current.
        let key_id = KeyId::generate();
        let device = DeviceCertificateSpec::new("example-laptop", key_id.clone(), NOW)
            .with_validity(NOW, NOW + time::Duration::days(1000));
        let ca =
            EphemeralCaSpec::new(key_id, NOW).with_validity(NOW, NOW + time::Duration::days(500));

        let error = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap_err();
        assert!(error.to_string().contains("at least as long"), "{error}");
    }

    #[test]
    fn the_output_type_exposes_no_private_key() {
        // A compile-time guarantee expressed as a test: the only fields are the
        // two public certificates, so no caller can persist a CA key.
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        let output = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();

        let rendered = format!("{output:?}");
        for forbidden in ["PRIVATE KEY", "private_key", "ca_key", "secret"] {
            assert!(!rendered.contains(forbidden), "{forbidden} in {rendered}");
        }
    }

    #[test]
    fn no_private_key_material_appears_in_the_persisted_pem() {
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        let output = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();

        let bundle = output.chain_pem();
        assert!(!bundle.contains("PRIVATE KEY"), "{bundle}");
        assert_eq!(bundle.matches("BEGIN CERTIFICATE").count(), 2);
        // Leaf first, as the file is documented.
        assert!(bundle.starts_with(&output.device_certificate.to_pem()));
    }

    #[test]
    fn no_chain_is_presented_because_the_ca_is_the_trust_anchor() {
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        let output = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();
        assert!(output.chain_der().is_empty());
    }

    #[test]
    fn each_bootstrap_uses_a_fresh_ca() {
        // Two bootstraps must not share a CA key, or revoking one trust anchor
        // would not revoke the other device.
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        let first = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();
        let second = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();
        assert_ne!(first.ca_fingerprint(), second.ca_fingerprint());
        assert_ne!(
            first.ca_certificate.public_key_sec1,
            second.ca_certificate.public_key_sec1
        );
    }

    #[test]
    fn issued_certificates_have_distinct_serial_numbers() {
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        let first = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();
        let second = issue(
            &testing::random_device_key().public_key_sec1(),
            &device,
            &ca,
            NOW,
        )
        .unwrap();
        assert_ne!(
            first.device_certificate.serial_decimal,
            second.device_certificate.serial_decimal
        );
    }

    #[test]
    fn an_invalid_device_public_key_is_refused() {
        let key_id = KeyId::generate();
        let (device, ca) = specs(&key_id);
        // Not a point on the curve, and not even uncompressed-formatted.
        let mut bogus = [0u8; 65];
        bogus[0] = 0x02;
        assert!(issue(&bogus, &device, &ca, NOW).is_err());
    }
}
