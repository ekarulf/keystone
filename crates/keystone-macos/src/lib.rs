//! The Secure Enclave backend.
//!
//! This is the crate that owns Keystone's security boundary: a P-256 signing key
//! generated inside the Secure Enclave, which cannot be exported and can only be
//! used through [`enclave::SecureEnclaveIdentity`].
//!
//! Two rules from the design shape everything here.
//!
//! *No silent fallback.* There is no software signer in this crate, not even
//! behind a feature flag. On a machine without a Secure Enclave — or in a build
//! for a non-macOS target — every operation returns
//! [`KeystoneError::SecureEnclaveUnavailable`] rather than degrading to a
//! software key.
//!
//! *No silent user-presence requirement.* Keys are created with an access-control
//! policy carrying no `USER_PRESENCE`, `BIOMETRY_*`, or `DEVICE_PASSCODE` flag, so
//! routine credential refresh never raises a Touch ID prompt. See [`access`].
//!
//! [`KeystoneError::SecureEnclaveUnavailable`]: keystone_core::error::KeystoneError::SecureEnclaveUnavailable

pub mod access;
pub mod aws;
pub mod enclave;

pub use access::{AccessPolicy, EnclaveReport};
pub use aws::CertificateIdentity;
pub use enclave::{is_available, require_available, SecureEnclaveIdentity};
