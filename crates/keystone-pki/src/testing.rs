//! Software test doubles for the PKI layer.
//!
//! Everything here uses an ordinary in-memory P-256 key, so the certificate and
//! validation code can be exercised without a Secure Enclave. Nothing in this
//! module is reachable from a release build: it is gated behind `cfg(test)` and
//! the `testing` feature, which the CLI never enables. That matters because a
//! software key that could stand in for a Secure Enclave key at runtime would be
//! exactly the "silent software identity" the design forbids.

use keystone_core::error::Result;
use keystone_core::identity::KeyId;
use keystone_core::signer::{DerEcdsaSignature, KeystoneSigningIdentity};
use p256::ecdsa::signature::Signer as _;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, PublicKeyData,
    SignatureAlgorithm,
};
use time::OffsetDateTime;

use crate::params::{DeviceCertificateSpec, EphemeralCaSpec};
use crate::signature::raw_to_der;

/// A fixed point in time for tests that do not care which one.
pub const TEST_NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

/// A software stand-in for a Secure Enclave signing key.
///
/// Signs the same way CryptoKit does — SHA-256 internally, then converted from
/// raw `r || s` to DER — so the conversion path is exercised rather than bypassed.
pub struct TestDeviceKey {
    key_id: KeyId,
    signing_key: p256::ecdsa::SigningKey,
}

impl TestDeviceKey {
    pub fn generate(key_id: KeyId) -> Self {
        Self {
            key_id,
            signing_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
        }
    }

    /// The 65-byte uncompressed SEC1 public key.
    pub fn public_key_sec1(&self) -> [u8; 65] {
        let encoded = self.signing_key.verifying_key().to_encoded_point(false);
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(encoded.as_bytes());
        bytes
    }

    /// Sign a message the way the Secure Enclave does, returning DER.
    pub fn sign_der(&self, message: &[u8]) -> DerEcdsaSignature {
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
        raw_to_der(&signature.to_bytes()).expect("a p256 signature converts to DER")
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
}

impl KeystoneSigningIdentity for TestDeviceKey {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        Ok(TestDeviceKey::public_key_sec1(self))
    }

    fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature> {
        Ok(self.sign_der(message))
    }
}

/// A device key with a random ID.
pub fn random_device_key() -> TestDeviceKey {
    TestDeviceKey::generate(KeyId::generate())
}

/// Names a public key to rcgen without holding its private half.
struct BorrowedPublicKey<'a> {
    sec1: &'a [u8],
}

impl PublicKeyData for BorrowedPublicKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.sec1
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

/// A software CA that keeps its key, so tests can issue several certificates.
///
/// The production CA in [`crate::ephemeral_ca`] deliberately cannot do this.
pub struct TestCa {
    key_pair: KeyPair,
    params: CertificateParams,
    certificate_der: Vec<u8>,
}

impl TestCa {
    /// A CA for a random key ID.
    pub fn generate() -> Self {
        Self::with_key_id(&KeyId::generate())
    }

    /// A CA whose subject names `key_id`.
    ///
    /// Two CAs built with the same key ID share a subject name but not a key,
    /// which is how the chain tests check that signatures are verified rather
    /// than just names compared.
    pub fn with_key_id(key_id: &KeyId) -> Self {
        let spec = EphemeralCaSpec::new(key_id.clone(), TEST_NOW - time::Duration::days(1));
        let params = spec.to_params().expect("valid CA params");
        let key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("can generate a CA key");
        let certificate_der = params
            .self_signed(&key_pair)
            .expect("can self-sign a CA certificate")
            .der()
            .to_vec();
        Self {
            key_pair,
            params,
            certificate_der,
        }
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn certificate_pem(&self) -> String {
        crate::certificate::encode_pem("CERTIFICATE", &self.certificate_der)
    }

    fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key_pair)
    }

    fn sign(&self, params: &CertificateParams, public_key_sec1: &[u8]) -> Vec<u8> {
        params
            .signed_by(
                &BorrowedPublicKey {
                    sec1: public_key_sec1,
                },
                &self.issuer(),
            )
            .expect("can sign a certificate")
            .der()
            .to_vec()
    }

    /// Issue a well-formed Keystone device certificate.
    pub fn issue_device_certificate(
        &self,
        key: &TestDeviceKey,
        device_name: &str,
        key_id: &KeyId,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Vec<u8> {
        let params = DeviceCertificateSpec::new(device_name, key_id.clone(), not_before)
            .with_validity(not_before, not_after)
            .to_params()
            .expect("valid device params");
        self.sign(&params, &key.public_key_sec1())
    }

    /// Issue a certificate whose only URI SAN is `uri`, or none at all.
    ///
    /// Used to check that a certificate without Keystone's device SAN is refused.
    pub fn issue_certificate_with_uri_san(
        &self,
        key: &TestDeviceKey,
        device_name: &str,
        uri: Option<&str>,
    ) -> Vec<u8> {
        let mut params = base_params(device_name);
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        if let Some(uri) = uri {
            params.subject_alt_names = vec![rcgen::SanType::URI(
                uri.to_string().try_into().expect("valid IA5 string"),
            )];
        }
        self.sign(&params, &key.public_key_sec1())
    }

    /// Issue a certificate that carries the device SAN but cannot sign.
    pub fn issue_certificate_without_digital_signature(
        &self,
        key: &TestDeviceKey,
        key_id: &KeyId,
    ) -> Vec<u8> {
        let mut params = base_params("example-laptop");
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        // Present but wrong: key agreement instead of digital signature.
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyAgreement];
        params.subject_alt_names = vec![rcgen::SanType::URI(
            key_id
                .device_san_uri()
                .try_into()
                .expect("valid IA5 string"),
        )];
        self.sign(&params, &key.public_key_sec1())
    }
}

fn base_params(common_name: &str) -> CertificateParams {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.not_before = TEST_NOW - time::Duration::days(1);
    params.not_after = TEST_NOW + time::Duration::days(365);
    params
}

/// A leaf and its issuing CA, with the device key that matches the leaf.
pub struct DeviceBundle {
    pub key_id: KeyId,
    pub device_name: String,
    pub device_public_key: [u8; 65],
    pub device_key: TestDeviceKey,
    ca: TestCa,
    leaf_der: Vec<u8>,
}

impl DeviceBundle {
    pub fn leaf_der(&self) -> &[u8] {
        &self.leaf_der
    }

    pub fn ca_der(&self) -> &[u8] {
        self.ca.certificate_der()
    }

    pub fn ca(&self) -> &TestCa {
        &self.ca
    }
}

/// A fresh, valid device bundle: the usual starting point for a test.
pub fn device_bundle() -> DeviceBundle {
    let key_id = KeyId::generate();
    let device_name = "example-laptop".to_string();
    let device_key = TestDeviceKey::generate(key_id.clone());
    let ca = TestCa::with_key_id(&key_id);
    let leaf_der = ca.issue_device_certificate(
        &device_key,
        &device_name,
        &key_id,
        TEST_NOW - time::Duration::days(1),
        TEST_NOW + time::Duration::days(5 * 365),
    );
    DeviceBundle {
        key_id,
        device_name,
        device_public_key: device_key.public_key_sec1(),
        device_key,
        ca,
        leaf_der,
    }
}

/// A self-signed certificate on a curve Keystone cannot use.
///
/// For the tests that check a non-P-256 certificate is refused at parse time.
pub fn certificate_with_other_algorithm(algorithm: &'static SignatureAlgorithm) -> Vec<u8> {
    let key_pair = KeyPair::generate_for(algorithm).expect("can generate a key");
    let mut params = base_params("not-a-keystone-device");
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params
        .self_signed(&key_pair)
        .expect("can self-sign")
        .der()
        .to_vec()
}
