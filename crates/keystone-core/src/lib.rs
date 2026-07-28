//! Portable Keystone types: configuration, identity metadata, credentials,
//! the private-key interface, and the error model.
//!
//! This crate is platform-independent on purpose. The Secure Enclave lives in
//! `keystone-macos` behind the [`signer::KeystoneSigningIdentity`] trait, which
//! keeps the security-critical surface small and lets the AWS protocol layer be
//! tested with a software key.

pub mod config;
pub mod credentials;
pub mod error;
pub mod identity;
pub mod redact;
pub mod signer;
pub mod store;
pub mod time;

pub use config::{
    Config, IssuerMetadata, IssuerMode, KeyAccessibility, Paths, Profile, ReadyProfile,
};
pub use credentials::{AwsSessionCredentials, CredentialProcessOutput};
pub use error::{KeystoneError, Result};
pub use identity::{IdentityMetadata, KeyId, KeyType, Sha256Fingerprint};
pub use signer::{DerEcdsaSignature, KeystoneSigningIdentity, PrehashedSigner};
pub use store::Store;
pub use time::{Clock, FixedClock, SystemClock};
