//! The IAM Roles Anywhere `CreateSession` client.
//!
//! This crate turns an X.509 signing identity into temporary AWS credentials.
//! It knows nothing about the Secure Enclave: callers supply an
//! [`request::AwsX509Identity`], which `keystone-macos` implements over a
//! hardware key and [`testing::TestIdentity`] implements over a software key
//! for tests.
//!
//! The signing details are ported from the official AWS credential helper; see
//! [`signing`] for the specific ways Roles Anywhere departs from SigV4.

pub mod client;
pub mod request;
pub mod response;
pub mod retry;
pub mod signing;

/// A software-key identity, for tests and differential comparison only.
///
/// Gated on the `testing` feature (enabled automatically for this crate's own
/// tests) so a software signing key cannot be reached from a release build of
/// the CLI. Keystone never falls back to a software identity in production.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use client::{RolesAnywhereClient, TransportConfig};
pub use request::{
    endpoint_for_region, AwsX509Identity, CreateSessionRequest, RolesAnywhereRequestSigner,
    SignedRequest,
};
pub use response::SessionResult;
pub use retry::RetryPolicy;
