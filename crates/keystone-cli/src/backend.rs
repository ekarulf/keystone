//! Which hardware key store this build uses.
//!
//! Keystone has two backends — the Secure Enclave and the Windows TPM — with the
//! same shape and the same guarantees. Selecting between them in one module means
//! the commands are written once: they refer to [`DeviceKey`], [`KeyPolicy`], and
//! [`CertificateIdentity`] without knowing which platform supplies them.
//!
//! The choice is made at compile time, by target, and there is no runtime
//! selection and no configuration for it. A machine has the key store its hardware
//! has; offering a choice would only offer a way to pick the weaker one.
//!
//! A target that is neither macOS nor Windows gets the Secure Enclave backend,
//! whose non-macOS build is a fail-closed stub. That is deliberate: an unsupported
//! platform must produce "no hardware-backed key store is available", not a
//! working software key.

#[cfg(not(windows))]
mod selected {
    pub use keystone_macos::aws::CertificateIdentity;
    pub use keystone_macos::enclave::SecureEnclaveIdentity as DeviceKey;
    pub use keystone_macos::AccessPolicy as KeyPolicy;

    /// The name to print for this key store.
    pub const KEY_STORE: &str = "Secure Enclave";

    pub fn report() -> super::KeyStoreReport {
        let report = keystone_macos::enclave::report();
        super::KeyStoreReport {
            available: report.available,
            detail: report.detail,
        }
    }
}

#[cfg(windows)]
mod selected {
    pub use keystone_windows::aws::CertificateIdentity;
    pub use keystone_windows::tpm::TpmIdentity as DeviceKey;
    pub use keystone_windows::TpmPolicy as KeyPolicy;

    /// The name to print for this key store.
    pub const KEY_STORE: &str = "TPM";

    pub fn report() -> super::KeyStoreReport {
        let report = keystone_windows::tpm::report();
        super::KeyStoreReport {
            available: report.available,
            detail: report.detail,
        }
    }
}

pub use selected::{report, CertificateIdentity, DeviceKey, KeyPolicy, KEY_STORE};

/// What the key store reports about this machine, for `keystone doctor`.
///
/// The two backends' report types are structurally identical but distinct, so they
/// are normalized here rather than making every caller cfg on the platform.
/// `supported_platform` is dropped: it only ever distinguishes "wrong build" from
/// "no hardware", and both are already spelled out in `detail`.
pub struct KeyStoreReport {
    pub available: bool,
    pub detail: Option<String>,
}
