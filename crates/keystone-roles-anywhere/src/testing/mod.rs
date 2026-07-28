//! Test doubles for the `CreateSession` path.
//!
//! [`TestIdentity`] exists so the AWS protocol layer can be exercised without a
//! Secure Enclave, and so golden and differential tests can use a key the
//! official helper can also load. It is compiled only for tests and behind the
//! `testing` feature — Keystone never falls back to a software key in
//! production.
//!
//! [`stub_server`] lives here rather than in this crate's `tests/` directory so
//! that `keystone-macos` can drive the same harness with a real Secure Enclave
//! key: the Phase 1 deliverable is the *same* end-to-end exchange with the
//! signer swapped, and a second copy of the server could drift from this one.

pub mod stub_server;

use keystone_core::error::Result;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::request::AwsX509Identity;

/// An identity backed by an in-memory P-256 key.
pub struct TestIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    leaf_der: Vec<u8>,
    chain_der: Vec<Vec<u8>>,
    serial_decimal: String,
}

impl TestIdentity {
    /// Create an identity with a random key and placeholder certificate bytes.
    ///
    /// The certificate bytes need not parse: the signing layer only base64
    /// encodes them, and the tests that need a real certificate build one with
    /// `keystone-pki`.
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            leaf_der: b"test-leaf-certificate-der".to_vec(),
            chain_der: Vec::new(),
            serial_decimal: "4837201".to_string(),
        }
    }

    /// Build an identity from a specific key and certificate, for golden and
    /// differential tests.
    pub fn from_parts(signing_key: SigningKey, leaf_der: Vec<u8>, serial_decimal: String) -> Self {
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            leaf_der,
            chain_der: Vec::new(),
            serial_decimal,
        }
    }

    pub fn with_chain(mut self, chain: Vec<Vec<u8>>) -> Self {
        self.chain_der = chain;
        self
    }

    pub fn with_serial(mut self, serial_decimal: impl Into<String>) -> Self {
        self.serial_decimal = serial_decimal.into();
        self
    }

    /// Verify a DER signature over `message`, hashing with SHA-256.
    pub fn verify(&self, message: &[u8], signature_der: &[u8]) -> bool {
        match Signature::from_der(signature_der) {
            Ok(signature) => self.verifying_key.verify(message, &signature).is_ok(),
            Err(_) => false,
        }
    }

    /// The SEC1 uncompressed public key.
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }
}

impl Default for TestIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl AwsX509Identity for TestIdentity {
    fn certificate_serial_decimal(&self) -> Result<String> {
        Ok(self.serial_decimal.clone())
    }

    fn leaf_certificate_der(&self) -> &[u8] {
        &self.leaf_der
    }

    fn certificate_chain_der(&self) -> &[Vec<u8>] {
        &self.chain_der
    }

    fn sign_string_to_sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>> {
        // Hashes internally with SHA-256, matching CryptoKit's `signature(for:)`
        // and the official helper's `Sign(rand, stringToSign, crypto.SHA256)`.
        let signature: Signature = self.signing_key.sign(string_to_sign);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}
