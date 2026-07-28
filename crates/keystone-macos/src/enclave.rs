//! The Secure Enclave signing identity.
//!
//! [`SecureEnclaveIdentity`] is a handle to a P-256 key that lives inside the
//! Secure Enclave. It can report its public key and sign a message; there is no
//! method that exports the private key, because CryptoKit provides none.
//!
//! ## Hashing
//!
//! CryptoKit's `SecureEnclave.P256.Signing.PrivateKey.signature(for:)` takes a
//! *message* and applies SHA-256 itself, then returns the fixed-width `r || s`
//! form. So [`SecureEnclaveIdentity`] implements
//! [`KeystoneSigningIdentity`](keystone_core::signer::KeystoneSigningIdentity) —
//! which is defined to hash internally — and not
//! [`PrehashedSigner`](keystone_core::signer::PrehashedSigner). Passing a digest
//! to this backend would hash it a second time and produce a signature AWS
//! rejects with an error that never mentions hashing.
//!
//! ## Fail closed
//!
//! Every constructor checks Secure Enclave availability first, and there is no
//! software path. A failure to generate, restore, or sign is an error, never a
//! fallback.

use keystone_core::config::KeyAccessibility;
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::{IdentityMetadata, KeyId, KeyType, Sha256Fingerprint};
use keystone_core::signer::{DerEcdsaSignature, KeystoneSigningIdentity};
use time::OffsetDateTime;

use crate::access::{AccessPolicy, EnclaveReport};

/// The message signed to prove a newly generated or restored key works.
///
/// Distinct from anything AWS would ever ask for, so a captured probe signature
/// is not a usable credential.
const SELF_TEST_MESSAGE: &[u8] = b"keystone secure enclave self test";

/// Whether this Mac has a usable Secure Enclave.
///
/// Returns `Ok(false)` rather than an error when the hardware is simply absent:
/// `keystone doctor` reports that as a diagnosis, not a failure to diagnose.
pub fn is_available() -> Result<bool> {
    backend::is_available()
}

/// Fail unless a Secure Enclave is available.
pub fn require_available() -> Result<()> {
    if backend::is_available()? {
        Ok(())
    } else {
        Err(KeystoneError::SecureEnclaveUnavailable)
    }
}

/// Describe the Secure Enclave for `keystone doctor`.
pub fn report() -> EnclaveReport {
    backend::report()
}

/// A P-256 signing key held in the Secure Enclave.
///
/// The public key is cached at construction because every code path that has an
/// identity has already exported and checked it; re-exporting on each call would
/// add a failure mode to an infallible-looking accessor.
pub struct SecureEnclaveIdentity {
    key_id: KeyId,
    public_key_sec1: [u8; 65],
    accessibility: KeyAccessibility,
    key: backend::EnclaveKey,
}

/// A freshly generated identity, together with the metadata to persist.
///
/// The two are returned together so a caller cannot persist metadata for one key
/// while holding another: `keystone init` writes `metadata` and uses `identity`
/// in the same process.
pub struct GeneratedIdentity {
    pub identity: SecureEnclaveIdentity,
    pub metadata: IdentityMetadata,
}

impl SecureEnclaveIdentity {
    /// Generate a new Secure Enclave key for `key_id`.
    ///
    /// The key is created with [`AccessPolicy`]'s flag-free access control, so it
    /// never prompts. Before returning, the key signs and verifies a probe: a key
    /// that cannot sign must fail here, not at the first credential refresh.
    pub fn generate(
        key_id: KeyId,
        policy: AccessPolicy,
        created_at: OffsetDateTime,
    ) -> Result<GeneratedIdentity> {
        require_available()?;

        let key = backend::EnclaveKey::generate(policy)?;
        let public_key_sec1 = key.public_key_sec1()?;
        let reference = key.opaque_reference()?;

        let identity = Self {
            key_id: key_id.clone(),
            public_key_sec1,
            accessibility: policy.accessibility(),
            key,
        };
        identity.self_test()?;

        let metadata = IdentityMetadata::new(key_id, &public_key_sec1, &reference, created_at);
        Ok(GeneratedIdentity { identity, metadata })
    }

    /// Restore the key described by persisted identity metadata.
    ///
    /// The public key CryptoKit reports is compared against the one recorded in
    /// the metadata. This is not a formality: CryptoKit accepts a data
    /// representation whose non-structural bytes have been altered and hands back
    /// a working key, so without this check a tampered or swapped identity file
    /// could quietly point Keystone at a key its certificate does not name — which
    /// would surface only as an opaque AWS rejection.
    pub fn restore(metadata: &IdentityMetadata, policy: AccessPolicy) -> Result<Self> {
        metadata.validate()?;
        if metadata.key_type != KeyType::SecureEnclaveP256Signing {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "identity {} is not a Secure Enclave signing key",
                metadata.key_id
            )));
        }
        require_available()?;

        let expected = metadata.public_key_sec1_bytes()?;
        let reference = metadata.opaque_key_reference_bytes()?;
        if reference.is_empty() {
            return Err(KeystoneError::KeyUnavailable);
        }

        let key = backend::EnclaveKey::restore(&reference)?;
        let public_key_sec1 = key.public_key_sec1()?;
        if public_key_sec1 != expected {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "identity {} names public key {}, but the Secure Enclave key reference resolves \
                 to {}; the identity file may have been replaced",
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
    /// Used by `keystone doctor` and after generation. The signature is checked
    /// against the cached public key, which catches a raw-to-DER conversion fault
    /// as well as a broken key.
    pub fn self_test(&self) -> Result<()> {
        let signature = self.sign_message_ecdsa_sha256(SELF_TEST_MESSAGE)?;
        keystone_pki::verify_der_signature(
            &self.public_key_sec1,
            SELF_TEST_MESSAGE,
            signature.as_bytes(),
        )
        .map_err(|_| {
            KeystoneError::SecureEnclave(
                "the Secure Enclave produced a signature that does not verify against its own \
                 public key"
                    .to_string(),
            )
        })
    }

    /// The SHA-256 fingerprint of the public key, safe to log.
    pub fn public_key_fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of(&self.public_key_sec1)
    }

    /// The accessibility this identity was opened with.
    pub fn accessibility(&self) -> KeyAccessibility {
        self.accessibility
    }
}

impl KeystoneSigningIdentity for SecureEnclaveIdentity {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        Ok(self.public_key_sec1)
    }

    /// Sign `message`, letting CryptoKit apply SHA-256.
    ///
    /// CryptoKit returns the 64-byte `r || s` form; AWS, X.509, and PKCS#10 all
    /// want DER, so the conversion happens here and nowhere else.
    fn sign_message_ecdsa_sha256(&self, message: &[u8]) -> Result<DerEcdsaSignature> {
        let raw = self.key.sign(message)?;
        keystone_pki::raw_to_der(&raw)
    }
}

/// Prints the key ID and public-key fingerprint only.
///
/// The design forbids logging "opaque Secure Enclave key references", and a
/// derived `Debug` on the backend handle would print a raw pointer that is
/// useless to a reader and noisy in a bug report.
impl std::fmt::Debug for SecureEnclaveIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureEnclaveIdentity")
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
        // Deliberately omits `metadata`, whose `opaque_key_reference` must not
        // reach a log.
        f.debug_struct("GeneratedIdentity")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "macos")]
mod backend {
    //! The CryptoKit backend.

    use cryptokit::error::CryptoKitError;
    use cryptokit::secure_enclave::{
        self, SecureEnclaveAuthenticationContext, SecureEnclaveSigningPrivateKey,
    };
    use keystone_core::error::{KeystoneError, Result};

    use crate::access::{AccessPolicy, EnclaveReport};

    pub(super) fn is_available() -> Result<bool> {
        secure_enclave::is_available().map_err(|error| {
            KeystoneError::SecureEnclave(format!(
                "cannot determine whether a Secure Enclave is present: {}",
                error.message()
            ))
        })
    }

    pub(super) fn report() -> EnclaveReport {
        match is_available() {
            Ok(true) => EnclaveReport {
                available: true,
                supported_platform: true,
                detail: None,
            },
            Ok(false) => EnclaveReport {
                available: false,
                supported_platform: true,
                detail: Some(
                    "this Mac reports no Secure Enclave; Keystone requires Apple silicon or a \
                     T2 Mac"
                        .to_string(),
                ),
            },
            Err(error) => EnclaveReport {
                available: false,
                supported_platform: true,
                detail: Some(error.to_string()),
            },
        }
    }

    /// A live CryptoKit key handle.
    ///
    /// The authentication context is kept alongside the key it was opened with, so
    /// the context cannot be released while the key still refers to it.
    pub(super) struct EnclaveKey {
        key: SecureEnclaveSigningPrivateKey,
        _context: Option<SecureEnclaveAuthenticationContext>,
    }

    impl EnclaveKey {
        pub(super) fn generate(policy: AccessPolicy) -> Result<Self> {
            let access_control = policy.to_cryptokit();
            // `compact_representable: false` keeps the key's public form the full
            // 65-byte uncompressed point that X.509 and AWS expect.
            let key = SecureEnclaveSigningPrivateKey::generate_with_options(
                false,
                Some(&access_control),
                None,
            )
            .map_err(|error| generate_error(&error))?;
            Ok(Self {
                key,
                _context: None,
            })
        }

        pub(super) fn restore(reference: &[u8]) -> Result<Self> {
            // Interaction is forbidden rather than merely unnecessary. Keystone's
            // own keys carry no user-presence flag, so this changes nothing for
            // them; for a key that does require interaction it turns a dialog that
            // would hang a non-interactive `credential_process` into an error.
            let mut context = SecureEnclaveAuthenticationContext::new().map_err(|error| {
                KeystoneError::SecureEnclave(format!(
                    "cannot create an authentication context: {}",
                    error.message()
                ))
            })?;
            context.set_interaction_not_allowed(true).map_err(|error| {
                KeystoneError::SecureEnclave(format!(
                    "cannot forbid interactive authentication: {}",
                    error.message()
                ))
            })?;

            let key =
                SecureEnclaveSigningPrivateKey::from_data_representation_with_authentication_context(
                    reference,
                    Some(&context),
                )
                .map_err(|_| KeystoneError::KeyUnavailable)?;
            Ok(Self {
                key,
                _context: Some(context),
            })
        }

        pub(super) fn public_key_sec1(&self) -> Result<[u8; 65]> {
            let public_key = self.key.public_key().map_err(|error| {
                KeystoneError::SecureEnclave(format!(
                    "cannot export the public key: {}",
                    error.message()
                ))
            })?;
            // The ANSI X9.63 form of a P-256 public key is exactly SEC1
            // uncompressed: `0x04 || x || y`.
            let x963 = public_key.x963_representation().map_err(|error| {
                KeystoneError::SecureEnclave(format!(
                    "cannot encode the public key: {}",
                    error.message()
                ))
            })?;
            let sec1: [u8; 65] = x963.try_into().map_err(|bytes: Vec<u8>| {
                KeystoneError::SecureEnclave(format!(
                    "Secure Enclave public key is {} bytes, expected 65",
                    bytes.len()
                ))
            })?;
            if sec1[0] != 0x04 {
                return Err(KeystoneError::SecureEnclave(
                    "Secure Enclave public key is not an uncompressed SEC1 point".to_string(),
                ));
            }
            Ok(sec1)
        }

        pub(super) fn opaque_reference(&self) -> Result<Vec<u8>> {
            self.key.data_representation().map_err(|error| {
                KeystoneError::SecureEnclave(format!(
                    "cannot export the Secure Enclave key reference: {}",
                    error.message()
                ))
            })
        }

        /// Sign a message, returning the raw 64-byte `r || s`.
        pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            // `signature(for:)` hashes the message with SHA-256 internally.
            self.key.sign(message).map_err(|error| {
                KeystoneError::SecureEnclave(format!(
                    "the Secure Enclave refused to sign: {}",
                    error.message()
                ))
            })
        }
    }

    /// Distinguish "no enclave" from "the enclave said no".
    ///
    /// The two need different remedies: the first means this Mac cannot run
    /// Keystone, the second usually means the access policy or Keychain state is
    /// wrong.
    fn generate_error(error: &CryptoKitError) -> KeystoneError {
        let message = error.message();
        if message.contains("unavailable") {
            KeystoneError::SecureEnclaveUnavailable
        } else {
            KeystoneError::SecureEnclave(format!("cannot generate a Secure Enclave key: {message}"))
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod backend {
    //! The fail-closed backend for non-macOS builds.
    //!
    //! Present so the crate still type-checks off macOS — for `cargo check` on a
    //! Linux CI runner, say. It has no software key: the design's "no silent
    //! fallback" rule means a build that cannot reach a Secure Enclave must refuse
    //! to sign, not sign with something else.

    use keystone_core::error::{KeystoneError, Result};

    use crate::access::{AccessPolicy, EnclaveReport};

    pub(super) fn is_available() -> Result<bool> {
        Ok(false)
    }

    pub(super) fn report() -> EnclaveReport {
        EnclaveReport::unsupported_platform()
    }

    /// Uninhabited: a non-macOS build cannot hold a Secure Enclave key at all.
    pub(super) enum EnclaveKey {}

    impl EnclaveKey {
        pub(super) fn generate(_policy: AccessPolicy) -> Result<Self> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }

        pub(super) fn restore(_reference: &[u8]) -> Result<Self> {
            Err(KeystoneError::SecureEnclaveUnavailable)
        }

        pub(super) fn public_key_sec1(&self) -> Result<[u8; 65]> {
            match *self {}
        }

        pub(super) fn opaque_reference(&self) -> Result<Vec<u8>> {
            match *self {}
        }

        pub(super) fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
            match *self {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    #[test]
    fn the_probe_message_is_not_an_aws_string_to_sign() {
        // A signature over the probe must not be replayable as a CreateSession
        // signature, so the probe must not look like one.
        let probe = String::from_utf8(SELF_TEST_MESSAGE.to_vec()).unwrap();
        assert!(!probe.contains("AWS4"));
        assert!(!probe.contains("aws4_request"));
    }

    /// Tests that need real hardware.
    ///
    /// Compiled only for macOS and skipped at runtime when no Secure Enclave is
    /// present, so the suite still passes in a VM — while a machine that does have
    /// one exercises the real path rather than a mock.
    #[cfg(target_os = "macos")]
    mod hardware {
        use super::*;

        /// SHA-256 of `message`.
        fn sha256(message: &[u8]) -> Vec<u8> {
            use sha2::{Digest as _, Sha256};
            Sha256::digest(message).to_vec()
        }

        /// Returns false when there is no enclave to test against.
        fn enclave_present() -> bool {
            match is_available() {
                Ok(available) => available,
                Err(error) => panic!("cannot query the Secure Enclave: {error}"),
            }
        }

        fn generate() -> Option<GeneratedIdentity> {
            if !enclave_present() {
                return None;
            }
            Some(
                SecureEnclaveIdentity::generate(KeyId::generate(), AccessPolicy::default(), NOW)
                    .expect("generating a Secure Enclave key"),
            )
        }

        #[test]
        fn a_generated_key_signs_without_a_prompt() {
            // The property `credential-process` depends on: this test would hang
            // or fail if the key required user presence.
            let Some(generated) = generate() else { return };
            generated.identity.self_test().unwrap();
        }

        #[test]
        fn the_public_key_is_an_uncompressed_sec1_point() {
            let Some(generated) = generate() else { return };
            let public_key = generated.identity.public_key_sec1().unwrap();
            assert_eq!(public_key[0], 0x04);
            // And it is a point the rest of Keystone can parse.
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key).unwrap();
        }

        #[test]
        fn a_signature_verifies_as_ecdsa_over_sha256_of_the_message() {
            // Confirms CryptoKit hashes internally. If it expected a digest
            // instead, verification of the message would fail here rather than as
            // an opaque AWS rejection later.
            let Some(generated) = generate() else { return };
            let message = b"AWS4-X509-ECDSA-SHA256\n20260726T011500Z\nscope\ndigest";
            let signature = generated
                .identity
                .sign_message_ecdsa_sha256(message)
                .unwrap();

            keystone_pki::verify_der_signature(
                &generated.identity.public_key_sec1().unwrap(),
                message,
                signature.as_bytes(),
            )
            .unwrap();

            // Had CryptoKit expected a digest, the signature would instead verify
            // against the digest treated as the message.
            let digest = sha256(message);
            assert!(
                keystone_pki::verify_der_signature(
                    &generated.identity.public_key_sec1().unwrap(),
                    &digest,
                    signature.as_bytes(),
                )
                .is_err(),
                "the enclave appears to sign a digest, not a message"
            );
        }

        #[test]
        fn a_restored_key_is_the_same_key() {
            // Step 3 and 4 of the design's integration test: restore across
            // processes and sign again.
            let Some(generated) = generate() else { return };
            let restored =
                SecureEnclaveIdentity::restore(&generated.metadata, AccessPolicy::default())
                    .unwrap();

            assert_eq!(restored.key_id(), generated.identity.key_id());
            assert_eq!(
                restored.public_key_sec1().unwrap(),
                generated.identity.public_key_sec1().unwrap()
            );

            let message = b"restored";
            let signature = restored.sign_message_ecdsa_sha256(message).unwrap();
            keystone_pki::verify_der_signature(
                &generated.identity.public_key_sec1().unwrap(),
                message,
                signature.as_bytes(),
            )
            .unwrap();
        }

        #[test]
        fn each_generated_key_is_distinct() {
            let Some(first) = generate() else { return };
            let Some(second) = generate() else { return };
            assert_ne!(
                first.identity.public_key_sec1().unwrap(),
                second.identity.public_key_sec1().unwrap()
            );
        }

        #[test]
        fn metadata_records_what_the_enclave_reported() {
            let Some(generated) = generate() else { return };
            let metadata = &generated.metadata;
            metadata.validate().unwrap();
            assert_eq!(metadata.key_type, KeyType::SecureEnclaveP256Signing);
            assert_eq!(
                metadata.public_key_sec1_bytes().unwrap(),
                generated.identity.public_key_sec1().unwrap()
            );
            assert!(!metadata.opaque_key_reference_bytes().unwrap().is_empty());
            assert_eq!(metadata.created_at, NOW);
        }

        #[test]
        fn a_swapped_public_key_in_the_metadata_is_refused() {
            // The check that matters most: CryptoKit will hand back a working key
            // for a reference whose recorded public key is wrong, so only this
            // comparison catches an identity file that has been edited or swapped.
            let Some(generated) = generate() else { return };
            let Some(other) = generate() else { return };

            let mut tampered = generated.metadata.clone();
            tampered.public_key_sec1 = other.metadata.public_key_sec1.clone();
            tampered.public_key_fingerprint_sha256 =
                other.metadata.public_key_fingerprint_sha256.clone();

            let error =
                SecureEnclaveIdentity::restore(&tampered, AccessPolicy::default()).unwrap_err();
            assert!(
                error.to_string().contains("may have been replaced"),
                "{error}"
            );
        }

        #[test]
        fn a_corrupt_key_reference_reports_an_unavailable_key() {
            let Some(generated) = generate() else { return };
            let mut broken = generated.metadata.clone();
            broken.opaque_key_reference = {
                use base64::prelude::{Engine as _, BASE64_STANDARD};
                let reference = generated.metadata.opaque_key_reference_bytes().unwrap();
                BASE64_STANDARD.encode(&reference[..reference.len() / 4])
            };

            assert!(matches!(
                SecureEnclaveIdentity::restore(&broken, AccessPolicy::default()),
                Err(KeystoneError::KeyUnavailable)
            ));
        }

        #[test]
        fn an_empty_key_reference_reports_an_unavailable_key() {
            let Some(generated) = generate() else { return };
            let mut empty = generated.metadata.clone();
            empty.opaque_key_reference = String::new();
            assert!(matches!(
                SecureEnclaveIdentity::restore(&empty, AccessPolicy::default()),
                Err(KeystoneError::KeyUnavailable)
            ));
        }

        #[test]
        fn metadata_from_an_unsupported_version_is_refused_before_the_enclave_is_touched() {
            let Some(generated) = generate() else { return };
            let mut future = generated.metadata.clone();
            future.version = 99;
            assert!(matches!(
                SecureEnclaveIdentity::restore(&future, AccessPolicy::default()),
                Err(KeystoneError::InvalidConfiguration(_))
            ));
        }

        #[test]
        fn a_when_unlocked_key_also_signs_while_the_screen_is_unlocked() {
            // Both configured accessibilities must produce a usable key. The
            // locked-screen and pre-first-unlock behaviors are what the design's
            // manual integration steps 5 through 10 cover; they cannot be asserted
            // from inside a test process.
            if !enclave_present() {
                return;
            }
            let policy = AccessPolicy::new(KeyAccessibility::WhenUnlocked);
            let generated = match SecureEnclaveIdentity::generate(KeyId::generate(), policy, NOW) {
                Ok(generated) => generated,
                // -25308 is `errSecInteractionNotAllowed`: a `WhenUnlocked` key
                // cannot be created while the screen is locked, which is the
                // accessibility working as specified rather than a defect. Only
                // this test can hit it — every other test uses the
                // after-first-unlock default.
                Err(error) if format!("{error}").contains("-25308") => return,
                Err(error) => panic!("generating a when-unlocked key: {error}"),
            };
            assert_eq!(
                generated.identity.accessibility(),
                KeyAccessibility::WhenUnlocked
            );
            generated.identity.self_test().unwrap();
        }

        #[test]
        fn debug_output_never_contains_the_key_reference() {
            let Some(generated) = generate() else { return };
            let rendered = format!("{:?} {:?}", generated, generated.identity);
            assert!(
                !rendered.contains(&generated.metadata.opaque_key_reference),
                "the opaque key reference must not be printable"
            );
            assert!(!rendered.contains(&generated.metadata.public_key_sec1));
            // But it must still identify the key well enough to be useful.
            assert!(rendered.contains(generated.identity.key_id().as_str()));
        }

        #[test]
        fn signing_the_same_message_twice_produces_different_signatures() {
            // ECDSA with a random nonce. Worth pinning: a deterministic signature
            // would mean the enclave was reusing k, and a golden test that asserted
            // signature bytes would be asserting the wrong thing.
            let Some(generated) = generate() else { return };
            let first = generated
                .identity
                .sign_message_ecdsa_sha256(b"same")
                .unwrap();
            let second = generated
                .identity
                .sign_message_ecdsa_sha256(b"same")
                .unwrap();
            assert_ne!(first, second);
        }
    }
}
