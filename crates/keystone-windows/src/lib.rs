//! The Windows TPM backend.
//!
//! The counterpart of `keystone-macos`, and it owns the same security boundary:
//! a P-256 signing key that cannot be exported and can only be used through
//! [`tpm::TpmIdentity`].
//!
//! The rules from the design are the same, and so are the consequences.
//!
//! *No silent fallback.* Only the TPM-backed Microsoft Platform Crypto Provider
//! is opened. There is no software signer here, not behind a feature flag and not
//! as a fallback when the TPM is missing; on a machine without one every
//! operation returns [`KeystoneError::SecureEnclaveUnavailable`]. That error name
//! reads oddly on Windows and is used deliberately: it is the design's
//! "hardware-backed key is unreachable" error, and adding a parallel variant would
//! let a caller handle one and miss the other.
//!
//! *No silent user-presence requirement.* Every CNG call passes
//! `NCRYPT_SILENT_FLAG`, so a key that would raise a provider dialog fails the
//! call instead of prompting. Windows Hello is not used: it would put a gesture in
//! front of every credential refresh, which the design forbids.
//!
//! One difference from macOS is worth stating, because it changes what "the same
//! key" means. CryptoKit hands back a wrapped blob that Keystone stores and later
//! restores. CNG persists the key in the TPM under a *name* and hands back
//! nothing; the name is what Keystone stores. So the identity file holds a name,
//! and [`tpm::TpmIdentity::restore`] proves the name still resolves to the same
//! key by comparing public keys — the name alone is not evidence, since anything
//! that can create keys could have replaced it.

pub mod access;
pub mod aws;
pub mod tpm;

pub use access::{TpmPolicy, TpmReport};
pub use aws::CertificateIdentity;
pub use tpm::{is_available, require_available, TpmIdentity};
