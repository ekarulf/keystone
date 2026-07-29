//! A P-256 signing key held in the TPM.
//!
//! Structured to mirror `keystone_macos::enclave` so the two backends can be read
//! side by side: [`is_available`], [`require_available`], [`report`], and a
//! [`TpmIdentity`] with `generate`, `restore`, and `self_test`.
//!
//! The one structural difference is how a key is named. CryptoKit returns a blob
//! Keystone stores and later restores; CNG persists the key itself under a name and
//! returns nothing storable. So the "opaque reference" here is a name, and
//! [`TpmIdentity::restore`] must treat it as untrusted input: a name is not proof
//! of identity, because anything able to create a TPM key could have created a
//! different key under the same name. The public-key comparison is what closes
//! that gap, exactly as it does on macOS for a different reason.

use keystone_core::config::KeyAccessibility;
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::{IdentityMetadata, KeyId, KeyType, Sha256Fingerprint};
use keystone_core::signer::{DerEcdsaSignature, KeystoneSigningIdentity, PrehashedSigner};
use time::OffsetDateTime;

use crate::access::{TpmPolicy, TpmReport};

/// The message signed to prove a newly generated or restored key works.
///
/// Distinct from anything AWS would ever ask for, so a captured probe signature is
/// not a usable credential. Byte-identical to the macOS backend's probe on purpose:
/// the two backends should be verifiable against each other.
const SELF_TEST_MESSAGE: &[u8] = b"keystone secure enclave self test";

/// The prefix of every Keystone CNG key name.
///
/// Namespaced so Keystone never opens, and above all never deletes, a TPM key some
/// other application persisted. The key ID follows this prefix.
const KEY_NAME_PREFIX: &str = "Keystone-";

/// The CNG key name for a Keystone key ID.
///
/// `KeyId` is already restricted to characters safe in a URI SAN, so it needs no
/// escaping to be a CNG name.
pub fn key_name_for(key_id: &KeyId) -> String {
    format!("{KEY_NAME_PREFIX}{key_id}")
}

/// Whether this machine has a usable TPM.
///
/// Returns `Ok(false)` rather than an error when the TPM is simply absent, so
/// `keystone doctor` reports that as a diagnosis rather than a failure to
/// diagnose.
pub fn is_available() -> Result<bool> {
    backend::is_available()
}

/// Fail unless a TPM is available.
pub fn require_available() -> Result<()> {
    if backend::is_available()? {
        Ok(())
    } else {
        Err(KeystoneError::SecureEnclaveUnavailable)
    }
}

/// Describe the TPM for `keystone doctor`.
pub fn report() -> TpmReport {
    backend::report()
}

/// A P-256 signing key held in the TPM.
///
/// The public key is cached at construction, matching the macOS backend: every
/// path that has an identity has already exported and checked it, and re-exporting
/// per call would add a failure mode to an accessor that looks infallible.
pub struct TpmIdentity {
    key_id: KeyId,
    public_key_sec1: [u8; 65],
    accessibility: KeyAccessibility,
    key: backend::PlatformKey,
}

/// A freshly generated identity, together with the metadata to persist.
pub struct GeneratedIdentity {
    pub identity: TpmIdentity,
    pub metadata: IdentityMetadata,
}

impl TpmIdentity {
    /// Generate a new TPM key for `key_id`.
    ///
    /// Refuses to overwrite an existing key of the same name. Overwriting would
    /// destroy the private key that an already-issued certificate names, turning a
    /// re-run of `keystone init` into silent, unrecoverable revocation of the
    /// device's identity.
    pub fn generate(
        key_id: KeyId,
        policy: TpmPolicy,
        created_at: OffsetDateTime,
    ) -> Result<GeneratedIdentity> {
        require_available()?;

        let name = key_name_for(&key_id);
        let key = backend::PlatformKey::create(&name)?;
        let public_key_sec1 = key.public_key_sec1()?;

        let identity = Self {
            key_id: key_id.clone(),
            public_key_sec1,
            accessibility: policy.accessibility(),
            key,
        };
        identity.self_test()?;

        // The reference is the CNG name, not a key blob. Stored as its UTF-8 bytes
        // so the metadata field's base64 encoding means the same thing for both
        // backends.
        let metadata = IdentityMetadata::with_key_type(
            key_id,
            KeyType::WindowsTpmP256Signing,
            &public_key_sec1,
            name.as_bytes(),
            created_at,
        );
        Ok(GeneratedIdentity { identity, metadata })
    }

    /// Restore the key described by persisted identity metadata.
    ///
    /// The public key CNG reports is compared against the one recorded in the
    /// metadata, and a mismatch is fatal. This is the check that makes storing a
    /// mere name safe: the name is attacker-influenceable input read from a file,
    /// and without this comparison a replaced identity file — or a TPM key created
    /// under the same name by anything else — would point Keystone at a key its
    /// certificate does not name, surfacing only as an opaque AWS rejection.
    pub fn restore(metadata: &IdentityMetadata, policy: TpmPolicy) -> Result<Self> {
        metadata.validate()?;
        if metadata.key_type != KeyType::WindowsTpmP256Signing {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "identity {} is a {} key, which cannot be used on Windows",
                metadata.key_id,
                metadata.key_type.platform()
            )));
        }
        require_available()?;

        let expected = metadata.public_key_sec1_bytes()?;
        let reference = metadata.opaque_key_reference_bytes()?;
        if reference.is_empty() {
            return Err(KeystoneError::KeyUnavailable);
        }
        let name = String::from_utf8(reference).map_err(|_| {
            KeystoneError::InvalidConfiguration(format!(
                "identity {} records a key reference that is not a valid CNG key name",
                metadata.key_id
            ))
        })?;
        // The name must be one Keystone issued. A metadata file naming some other
        // application's TPM key would otherwise have Keystone open it, and — via
        // `rotate` — delete it.
        if !name.starts_with(KEY_NAME_PREFIX) {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "identity {} names TPM key {name:?}, which is not a Keystone key; Keystone only \
                 uses keys named {KEY_NAME_PREFIX}*",
                metadata.key_id
            )));
        }

        let key = backend::PlatformKey::open(&name)?;
        let public_key_sec1 = key.public_key_sec1()?;
        if public_key_sec1 != expected {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "identity {} names public key {}, but TPM key {name} resolves to {}; the identity \
                 file may have been replaced",
                metadata.key_id,
                metadata.public_key_fingerprint_sha256.display_short(),
                Sha256Fingerprint::of(&public_key_sec1).display_short(),
            )));
        }

        Ok(Self {
            key_id: metadata.key_id.clone(),
            public_key_sec1,
            accessibility: policy.accessibility(),
            key,
        })
    }

    /// Sign and verify a probe message.
    ///
    /// The signature is checked against the cached public key, which catches a
    /// raw-to-DER conversion fault as well as a broken key.
    pub fn self_test(&self) -> Result<()> {
        let signature = self.sign_message_ecdsa_sha256(SELF_TEST_MESSAGE)?;
        keystone_pki::verify_der_signature(
            &self.public_key_sec1,
            SELF_TEST_MESSAGE,
            signature.as_bytes(),
        )
        .map_err(|_| {
            KeystoneError::SecureEnclave(
                "the TPM produced a signature that does not verify against its own public key"
                    .to_string(),
            )
        })
    }

    /// The SHA-256 fingerprint of the public key, safe to log.
    pub fn public_key_fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of(&self.public_key_sec1)
    }

    /// The accessibility this identity was opened with.
    ///
    /// Recorded rather than enforced on Windows; see [`TpmPolicy::describe`].
    pub fn accessibility(&self) -> KeyAccessibility {
        self.accessibility
    }

    /// Delete the underlying TPM key.
    ///
    /// Used by `keystone rotate` after the replacement identity is in place. The
    /// private key is unrecoverable afterwards, so the caller is responsible for
    /// ordering this after the new key works.
    pub fn delete_key(self) -> Result<()> {
        self.key.delete()
    }
}

impl KeystoneSigningIdentity for TpmIdentity {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        Ok(self.public_key_sec1)
    }

    /// Hash `message` with SHA-256, then sign the digest.
    ///
    /// The hashing is explicit because CNG signs a digest and applies no hash of
    /// its own — the opposite of CryptoKit. This is the exact spot the design warns
    /// about: "do not accidentally hash the Roles Anywhere string-to-sign twice".
    /// The string-to-sign arrives here as a message and is hashed once, here. A
    /// caller that has already hashed must use [`PrehashedSigner`] instead, which is
    /// why the two traits are separate.
    fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature> {
        use sha2::{Digest as _, Sha256};
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.sign_prehashed_sha256(&digest)
    }
}

impl PrehashedSigner for TpmIdentity {
    /// Sign a digest that the caller has already computed.
    ///
    /// CNG's native operation, so this is the primitive and
    /// [`KeystoneSigningIdentity::sign_message_ecdsa_sha256`] is the wrapper — the
    /// reverse of the macOS backend, where CryptoKit hashes internally.
    fn sign_prehashed_sha256(&self, digest: &[u8; 32]) -> Result<DerEcdsaSignature> {
        let raw = self.key.sign_prehashed(digest)?;
        keystone_pki::raw_to_der(&raw)
    }
}

/// Prints the key ID and public-key fingerprint only.
///
/// The design forbids logging opaque key references. The CNG name is less
/// sensitive than a wrapped blob, but it is still the handle to the private key and
/// still has no place in a bug report.
impl std::fmt::Debug for TpmIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmIdentity")
            .field("key_id", &self.key_id)
            .field(
                "public_key_fingerprint",
                &self.public_key_fingerprint().display_short(),
            )
            .field("accessibility", &self.accessibility.as_str())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for GeneratedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Omits `metadata`, whose `opaque_key_reference` must not reach a log.
        f.debug_struct("GeneratedIdentity")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
mod backend {
    //! The real CNG-backed implementation.

    use keystone_core::error::{KeystoneError, Result};
    use keystone_win32_sys::cng::{self, Provider, TpmKey, NTE_BAD_KEYSET, NTE_EXISTS};
    use keystone_win32_sys::Win32Error;

    use crate::access::TpmReport;

    /// Translate a Win32 failure into Keystone's error model.
    ///
    /// The two statuses that have a specific meaning to a user are mapped to
    /// specific variants; everything else keeps the raw status, because a
    /// `SECURITY_STATUS` is the only thing that makes an unfamiliar CNG failure
    /// searchable.
    fn map(error: Win32Error, context: &str) -> KeystoneError {
        match error.code {
            NTE_BAD_KEYSET => KeystoneError::KeyUnavailable,
            _ => KeystoneError::SecureEnclave(format!("{context}: {error}")),
        }
    }

    pub fn is_available() -> Result<bool> {
        cng::platform_provider_available()
            .map_err(|error| map(error, "cannot query the TPM key storage provider"))
    }

    pub fn report() -> TpmReport {
        match cng::platform_provider_available() {
            Ok(true) => TpmReport {
                available: true,
                supported_platform: true,
                detail: None,
            },
            Ok(false) => TpmReport {
                available: false,
                supported_platform: true,
                detail: Some(
                    "the Microsoft Platform Crypto Provider reported no usable TPM. Keystone \
                     requires a TPM 2.0 that is enabled in firmware; it will not fall back to a \
                     software key."
                        .to_string(),
                ),
            },
            Err(error) => TpmReport {
                available: false,
                supported_platform: true,
                detail: Some(format!("could not query the TPM: {error}")),
            },
        }
    }

    /// A live handle to a Keystone TPM key.
    ///
    /// Holds the provider alongside the key because CNG requires the provider
    /// handle to outlive keys opened from it.
    pub struct PlatformKey {
        // Field order is the drop order: the key is released before the provider
        // it came from.
        key: TpmKey,
        _provider: Provider,
    }

    impl PlatformKey {
        pub fn create(name: &str) -> Result<Self> {
            let provider = Provider::open_platform()
                .map_err(|error| map(error, "cannot open the TPM key storage provider"))?;
            let key = TpmKey::create(&provider, name).map_err(|error| {
                if error.code == NTE_EXISTS {
                    // Not mapped through `map`: this is a configuration problem
                    // with a specific remedy, not a TPM failure.
                    KeystoneError::InvalidConfiguration(format!(
                        "a TPM key named {name} already exists. Keystone will not overwrite it, \
                         because doing so would destroy the private key an existing certificate \
                         names. Use `keystone rotate` to replace an identity."
                    ))
                } else {
                    map(error, "cannot create a TPM key")
                }
            })?;
            Ok(Self {
                key,
                _provider: provider,
            })
        }

        pub fn open(name: &str) -> Result<Self> {
            let provider = Provider::open_platform()
                .map_err(|error| map(error, "cannot open the TPM key storage provider"))?;
            let key = TpmKey::open(&provider, name)
                .map_err(|error| map(error, "cannot open the TPM key"))?;
            Ok(Self {
                key,
                _provider: provider,
            })
        }

        pub fn public_key_sec1(&self) -> Result<[u8; 65]> {
            self.key
                .public_key_sec1()
                .map_err(|error| map(error, "cannot export the TPM public key"))
        }

        pub fn sign_prehashed(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
            self.key
                .sign_prehashed_sha256(digest)
                .map_err(|error| map(error, "the TPM could not sign"))
        }

        pub fn delete(self) -> Result<()> {
            // `_provider` must outlive the delete; destructuring keeps it alive
            // until the end of this function.
            let Self { key, _provider } = self;
            key.delete()
                .map_err(|error| map(error, "cannot delete the TPM key"))
        }
    }
}

#[cfg(not(windows))]
mod backend {
    //! The fail-closed stub for a non-Windows build.
    //!
    //! Every operation reports the hardware as unreachable. There is deliberately
    //! no software key here: the design forbids a software fallback, and a stub
    //! that signed would make a cross-compiled build silently insecure rather than
    //! obviously unusable.

    use keystone_core::error::{KeystoneError, Result};

    use crate::access::TpmReport;

    pub fn is_available() -> Result<bool> {
        Ok(false)
    }

    pub fn report() -> TpmReport {
        TpmReport::unsupported_platform()
    }

    pub struct PlatformKey;

    impl PlatformKey {
        pub fn create(_name: &str) -> Result<Self> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }

        pub fn open(_name: &str) -> Result<Self> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }

        pub fn public_key_sec1(&self) -> Result<[u8; 65]> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }

        pub fn sign_prehashed(&self, _digest: &[u8; 32]) -> Result<[u8; 64]> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }

        pub fn delete(self) -> Result<()> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_are_namespaced_to_keystone() {
        let key_id = KeyId::generate();
        let name = key_name_for(&key_id);
        assert!(name.starts_with(KEY_NAME_PREFIX), "{name}");
        assert!(name.ends_with(key_id.as_str()), "{name}");
    }

    #[test]
    fn distinct_key_ids_get_distinct_key_names() {
        // A collision would have two identities sharing one TPM key, so `rotate`
        // deleting one would silently break the other.
        assert_ne!(
            key_name_for(&KeyId::generate()),
            key_name_for(&KeyId::generate())
        );
    }

    #[test]
    fn a_secure_enclave_identity_is_refused_by_the_windows_backend() {
        // The cross-platform case: an identity directory copied from a Mac. The
        // error must name the platform rather than reporting corruption, and it
        // must be refused before the reference is used as a CNG name.
        let key_id = KeyId::generate();
        let metadata = IdentityMetadata::new(
            key_id,
            &[0x04; 65],
            b"a cryptokit blob",
            OffsetDateTime::UNIX_EPOCH,
        );
        let error = TpmIdentity::restore(&metadata, TpmPolicy::default()).unwrap_err();
        let message = format!("{error}");
        assert!(message.contains("macOS"), "{message}");
    }

    #[cfg(not(windows))]
    #[test]
    fn the_stub_backend_never_signs() {
        // "No silent fallback": on a non-Windows build every operation must fail
        // rather than produce a signature from some software key.
        assert!(matches!(
            backend::PlatformKey::create("Keystone-x"),
            Err(KeystoneError::SecureEnclaveUnavailable)
        ));
        assert!(matches!(
            backend::PlatformKey::open("Keystone-x"),
            Err(KeystoneError::SecureEnclaveUnavailable)
        ));
        assert!(!is_available().unwrap());
        assert!(matches!(
            require_available(),
            Err(KeystoneError::SecureEnclaveUnavailable)
        ));
        assert!(!report().supported_platform);
    }
}
