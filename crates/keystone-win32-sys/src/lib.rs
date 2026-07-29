//! The Win32 FFI quarantine.
//!
//! Every `unsafe` block Keystone executes on Windows lives in this crate, and
//! nowhere else. The workspace sets `unsafe_code = "forbid"`; CNG and the Win32
//! security APIs are raw FFI with no safe wrapper, so rather than relax that lint
//! across a crate that also holds logic, the FFI is confined here behind safe
//! signatures. Auditing Keystone's use of unsafe means reading this one
//! directory.
//!
//! Two modules, matching the two things Windows must provide that Unix gets from
//! the Secure Enclave and from file modes:
//!
//! * [`cng`] — a non-exportable P-256 signing key in the TPM, via the Microsoft
//!   Platform Crypto Provider.
//! * [`security`] — owner and DACL inspection, and creating a file whose DACL
//!   grants only the calling user. This is the analogue of the uid-and-mode check
//!   `keystone-core` performs on Unix, which has no meaning on Windows.
//!
//! On a non-Windows target every item here is absent. Callers reach this crate
//! only from `#[cfg(windows)]` code, so there is no stub to fall through to and
//! therefore no way to silently get a weaker guarantee on the wrong platform.

#![cfg(windows)]

pub mod cng;
pub mod security;

/// A failed Win32 or CNG call, carrying the status the API returned.
///
/// Kept as the raw value rather than mapped to a Keystone error: this crate is
/// the FFI boundary and has no opinion on how a failure should read. The backend
/// crate translates, where it knows which operation was being attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Error {
    /// A `SECURITY_STATUS` from CNG, or a `GetLastError` value.
    pub code: i32,
    /// The API that failed, as a static string, for the message.
    pub api: &'static str,
}

impl Win32Error {
    pub(crate) fn new(api: &'static str, code: i32) -> Self {
        Self { code, api }
    }

    /// `GetLastError`, for the APIs that report failure by return value.
    pub(crate) fn last(api: &'static str) -> Self {
        // SAFETY: `GetLastError` takes no arguments, reads thread-local state,
        // and cannot fail.
        #[allow(unsafe_code)]
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() } as i32;
        Self { code, api }
    }
}

impl std::fmt::Display for Win32Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Both forms are printed: the hex is what Microsoft's documentation and
        // most search results use for a SECURITY_STATUS, the decimal is what
        // `GetLastError` tables use.
        write!(
            f,
            "{} failed: 0x{:08x} ({})",
            self.api, self.code as u32, self.code
        )
    }
}

impl std::error::Error for Win32Error {}

pub type Result<T> = std::result::Result<T, Win32Error>;

/// Encode a Rust string as a NUL-terminated UTF-16 buffer for a `PCWSTR`.
///
/// The returned `Vec` must outlive the call it is passed to; every caller in this
/// crate keeps it in a local binding for exactly that reason.
pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
