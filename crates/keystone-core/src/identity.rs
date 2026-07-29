//! Keystone identity metadata: the public half of a hardware-held key.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::error::{KeystoneError, Result};
use crate::time::rfc3339;

/// A random, opaque identifier for one Keystone identity.
///
/// This is not derived from the key material: an identity keeps its ID even if
/// the certificate is reissued, and the ID appears in the device URI SAN, which
/// is the value IAM policies condition on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Generate a fresh random key ID (128 bits, lowercase hex).
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self(hex::encode(bytes))
    }

    /// Accept a key ID from configuration or a certificate SAN.
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "key id has implausible length: {} characters",
                value.len()
            )));
        }
        // Restricted so a key ID is always safe to interpolate into a URI SAN
        // and into generated CDK source without quoting concerns.
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(KeystoneError::InvalidConfiguration(
                "key id must contain only alphanumerics, '-', or '_'".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The URI SAN that identifies this device in certificates and IAM policies.
    pub fn device_san_uri(&self) -> String {
        format!("urn:keystone:device:{}", self.0)
    }

    /// Recover a key ID from a device URI SAN, if it is one.
    pub fn from_device_san_uri(uri: &str) -> Option<Self> {
        uri.strip_prefix("urn:keystone:device:")
            .and_then(|rest| Self::parse(rest).ok())
    }

    /// An abbreviated form for log lines and progress output.
    pub fn short(&self) -> String {
        abbreviate(&self.0)
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A SHA-256 fingerprint over some public artifact (a key or a certificate).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Fingerprint(String);

impl Sha256Fingerprint {
    /// Fingerprint arbitrary public bytes.
    pub fn of(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(KeystoneError::InvalidConfiguration(
                "fingerprint must be 64 hex characters".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A prefix, which is safe to log: it identifies without being a full hash.
    pub fn short(&self) -> String {
        abbreviate(&self.0)
    }

    /// The `SHA256:<prefix>` form used in human-facing output.
    pub fn display_short(&self) -> String {
        format!("SHA256:{}", self.short())
    }
}

impl std::fmt::Display for Sha256Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn abbreviate(value: &str) -> String {
    // Enough to be recognizable across a log or a support conversation; short
    // enough that nobody mistakes it for the full value.
    const PREFIX: usize = 12;
    if value.len() <= PREFIX {
        value.to_string()
    } else {
        format!("{}...", &value[..PREFIX])
    }
}

/// What kind of key backs an identity.
///
/// Recorded explicitly so Keystone can refuse an identity it does not understand
/// rather than misinterpreting its opaque reference. The two variants are not
/// interchangeable: the reference means different things, and a backend that read
/// the other's would either fail obscurely or, worse, resolve to some unrelated
/// key. Each backend checks this field before touching the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "secure-enclave-p256-signing")]
    SecureEnclaveP256Signing,
    /// A TPM key held by the Windows Platform Crypto Provider.
    ///
    /// Its `opaque_key_reference` is the CNG key *name* in UTF-8, not a wrapped
    /// key blob: CNG persists the key itself and hands back nothing to store.
    #[serde(rename = "windows-tpm-p256-signing")]
    WindowsTpmP256Signing,
}

impl KeyType {
    /// The platform this key can be used on, for an error that explains itself.
    ///
    /// An identity directory copied between a Mac and a PC is the case worth
    /// naming: the file is valid and the key is simply not reachable here, which
    /// is different from corruption.
    pub fn platform(self) -> &'static str {
        match self {
            Self::SecureEnclaveP256Signing => "macOS",
            Self::WindowsTpmP256Signing => "Windows",
        }
    }
}

/// The persisted public record of a Keystone identity.
///
/// `opaque_key_reference` is whatever the backend needs to find its key again,
/// and its meaning depends on `key_type`. Neither form is an exported private
/// scalar — the private key cannot be reconstructed from either on another device
/// — but it is the only handle to the key, so losing or replacing this file makes
/// the identity unusable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMetadata {
    pub version: u8,
    pub key_id: KeyId,
    pub key_type: KeyType,
    /// The 65-byte uncompressed SEC1 public key, base64-encoded.
    pub public_key_sec1: String,
    pub public_key_fingerprint_sha256: Sha256Fingerprint,
    /// The backend's handle to the private key, base64-encoded.
    ///
    /// CryptoKit's wrapped Secure Enclave blob for a Secure Enclave key; the CNG
    /// key name for a Windows TPM key. Base64 either way so the field's encoding
    /// does not depend on the variant.
    pub opaque_key_reference: String,
    #[serde(with = "rfc3339")]
    pub created_at: OffsetDateTime,
}

/// The current identity-metadata schema version.
pub const IDENTITY_VERSION: u8 = 1;

impl IdentityMetadata {
    /// Metadata for a Secure Enclave key.
    pub fn new(
        key_id: KeyId,
        public_key_sec1: &[u8; 65],
        opaque_key_reference: &[u8],
        created_at: OffsetDateTime,
    ) -> Self {
        Self::with_key_type(
            key_id,
            KeyType::SecureEnclaveP256Signing,
            public_key_sec1,
            opaque_key_reference,
            created_at,
        )
    }

    /// Metadata for a key of an explicitly named backend.
    ///
    /// [`new`](Self::new) remains the Secure Enclave constructor so that the
    /// macOS call sites cannot acquire a Windows key type by editing one
    /// argument.
    pub fn with_key_type(
        key_id: KeyId,
        key_type: KeyType,
        public_key_sec1: &[u8; 65],
        opaque_key_reference: &[u8],
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            version: IDENTITY_VERSION,
            key_id,
            key_type,
            public_key_sec1: BASE64_STANDARD.encode(public_key_sec1),
            public_key_fingerprint_sha256: Sha256Fingerprint::of(public_key_sec1),
            opaque_key_reference: BASE64_STANDARD.encode(opaque_key_reference),
            created_at,
        }
    }

    /// Decode the SEC1 public key, checking it is a well-formed uncompressed point.
    pub fn public_key_sec1_bytes(&self) -> Result<[u8; 65]> {
        let bytes = BASE64_STANDARD
            .decode(&self.public_key_sec1)
            .map_err(|e| KeystoneError::Other(format!("identity public key is not base64: {e}")))?;
        let bytes: [u8; 65] = bytes.try_into().map_err(|v: Vec<u8>| {
            KeystoneError::Other(format!(
                "identity public key must be 65 bytes, found {}",
                v.len()
            ))
        })?;
        if bytes[0] != 0x04 {
            return Err(KeystoneError::Other(
                "identity public key is not an uncompressed SEC1 point".to_string(),
            ));
        }
        Ok(bytes)
    }

    pub fn opaque_key_reference_bytes(&self) -> Result<Vec<u8>> {
        BASE64_STANDARD
            .decode(&self.opaque_key_reference)
            .map_err(|e| KeystoneError::Other(format!("key reference is not base64: {e}")))
    }

    /// Reject metadata written by an incompatible Keystone version.
    pub fn validate(&self) -> Result<()> {
        if self.version != IDENTITY_VERSION {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "identity metadata version {} is not supported (expected {IDENTITY_VERSION})",
                self.version
            )));
        }
        let bytes = self.public_key_sec1_bytes()?;
        let expected = Sha256Fingerprint::of(&bytes);
        if expected != self.public_key_fingerprint_sha256 {
            return Err(KeystoneError::InvalidConfiguration(
                "identity public-key fingerprint does not match the recorded public key"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_round_trips_through_a_device_san() {
        let key_id = KeyId::generate();
        let uri = key_id.device_san_uri();
        assert_eq!(KeyId::from_device_san_uri(&uri), Some(key_id));
    }

    #[test]
    fn generated_key_ids_are_distinct() {
        let a = KeyId::generate();
        let b = KeyId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn key_id_rejects_characters_that_would_escape_a_uri_san() {
        for bad in ["", "has space", "semi;colon", "urn:nested", "sla/sh"] {
            assert!(KeyId::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn non_keystone_uris_are_not_device_sans() {
        assert!(KeyId::from_device_san_uri("urn:example:device:abc").is_none());
        assert!(KeyId::from_device_san_uri("https://example.com").is_none());
        // Right prefix, but the ID itself is not acceptable.
        assert!(KeyId::from_device_san_uri("urn:keystone:device:has space").is_none());
    }

    #[test]
    fn fingerprints_are_lowercase_hex_of_sha256() {
        let fingerprint = Sha256Fingerprint::of(b"keystone");
        assert_eq!(fingerprint.as_str().len(), 64);
        assert_eq!(
            fingerprint,
            Sha256Fingerprint::parse(fingerprint.as_str().to_ascii_uppercase()).unwrap()
        );
    }

    #[test]
    fn fingerprint_parse_rejects_wrong_length_and_non_hex() {
        assert!(Sha256Fingerprint::parse("abc").is_err());
        assert!(Sha256Fingerprint::parse("z".repeat(64)).is_err());
    }

    #[test]
    fn short_forms_truncate_and_mark_truncation() {
        let fingerprint = Sha256Fingerprint::of(b"keystone");
        let short = fingerprint.short();
        assert!(short.ends_with("..."));
        assert!(fingerprint.as_str().starts_with(&short[..12]));
        assert!(fingerprint.display_short().starts_with("SHA256:"));
    }

    fn sample_metadata() -> IdentityMetadata {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x04;
        public_key[1] = 0x42;
        IdentityMetadata::new(
            KeyId::parse("019cabc").unwrap(),
            &public_key,
            b"opaque-reference",
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn identity_metadata_round_trips_through_json() {
        let metadata = sample_metadata();
        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let parsed: IdentityMetadata = serde_json::from_str(&json).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.key_id, metadata.key_id);
        assert_eq!(
            parsed.public_key_sec1_bytes().unwrap(),
            metadata.public_key_sec1_bytes().unwrap()
        );
        assert_eq!(
            parsed.opaque_key_reference_bytes().unwrap(),
            b"opaque-reference"
        );
        // The key type is spelled out in the file, so a future version can refuse it.
        assert!(json.contains("secure-enclave-p256-signing"));
    }

    #[test]
    fn identity_metadata_rejects_a_future_version() {
        let mut metadata = sample_metadata();
        metadata.version = IDENTITY_VERSION + 1;
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn identity_metadata_rejects_a_fingerprint_that_does_not_match_the_key() {
        let mut metadata = sample_metadata();
        metadata.public_key_fingerprint_sha256 = Sha256Fingerprint::of(b"a different key");
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn identity_metadata_rejects_a_compressed_public_key() {
        let mut metadata = sample_metadata();
        let mut compressed = [0u8; 65];
        compressed[0] = 0x02;
        metadata.public_key_sec1 = BASE64_STANDARD.encode(compressed);
        assert!(metadata.public_key_sec1_bytes().is_err());
    }
}
