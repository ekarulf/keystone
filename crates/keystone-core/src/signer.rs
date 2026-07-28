//! The private-key interface.
//!
//! This is Keystone's security boundary, so it is kept deliberately small: a
//! backend can export a public key and produce one specific kind of signature,
//! and nothing else.

use crate::error::Result;
use crate::identity::KeyId;

/// A DER-encoded ECDSA signature (`SEQUENCE { r INTEGER, s INTEGER }`).
///
/// X.509 and PKCS#10 both carry signatures in this form. The type exists so a
/// DER signature is never confused with the fixed-width `r || s` form that
/// CryptoKit returns natively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerEcdsaSignature(Vec<u8>);

impl DerEcdsaSignature {
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self(der.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A key that can sign on Keystone's behalf.
///
/// There is intentionally no generic `sign` method. The one signing operation
/// takes a message and hashes it internally with SHA-256, matching CryptoKit's
/// `signature(for:)`. A backend that can only sign a precomputed digest must
/// implement [`PrehashedSigner`] instead, so that the two cannot be mixed up —
/// hashing the Roles Anywhere string-to-sign twice produces a signature AWS
/// rejects with an error that does not mention hashing.
pub trait KeystoneSigningIdentity {
    fn key_id(&self) -> &KeyId;

    /// The 65-byte uncompressed SEC1 public key.
    fn public_key_sec1(&self) -> Result<[u8; 65]>;

    /// Sign `message`, hashing it with SHA-256 internally.
    fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature>;
}

/// A key that signs an already-computed SHA-256 digest.
///
/// Separate from [`KeystoneSigningIdentity`] so the caller must state which
/// convention it is using.
pub trait PrehashedSigner {
    /// Sign a 32-byte SHA-256 digest.
    fn sign_prehashed_sha256(&self, digest: &[u8; 32]) -> Result<DerEcdsaSignature>;
}

impl<T: KeystoneSigningIdentity + ?Sized> KeystoneSigningIdentity for &T {
    fn key_id(&self) -> &KeyId {
        (**self).key_id()
    }

    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        (**self).public_key_sec1()
    }

    fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature> {
        (**self).sign_message_ecdsa_sha256(message)
    }
}

impl<T: KeystoneSigningIdentity + ?Sized> KeystoneSigningIdentity for std::sync::Arc<T> {
    fn key_id(&self) -> &KeyId {
        (**self).key_id()
    }

    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        (**self).public_key_sec1()
    }

    fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature> {
        (**self).sign_message_ecdsa_sha256(message)
    }
}
