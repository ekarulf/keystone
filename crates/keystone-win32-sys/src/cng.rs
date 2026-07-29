//! A non-exportable P-256 signing key in the TPM, through CNG.
//!
//! The Windows counterpart of the Secure Enclave. The provider is the *Microsoft
//! Platform Crypto Provider*, which is TPM-backed; the software provider is never
//! opened, because "no fallback to a software private key" is a design rule, not
//! a preference. A machine without a usable TPM reports unavailable and Keystone
//! stops.
//!
//! Three properties are set on every key, and each one is load-bearing:
//!
//! * `NCRYPT_EXPORT_POLICY_PROPERTY` is set to `0`, so the private key cannot be
//!   exported even by the process that created it. The design's first prohibition
//!   is exporting the private key.
//! * `NCRYPT_KEY_USAGE_PROPERTY` is `NCRYPT_ALLOW_SIGNING_FLAG` alone, so the key
//!   cannot be repurposed for decryption or key agreement.
//! * `NCRYPT_SILENT_FLAG` is passed to every call that documents it, which
//!   suppresses any provider UI. This is the Windows form of "must not silently add
//!   biometric or user-presence requirements": a key that would prompt fails the
//!   call instead of raising a dialog during an unattended credential refresh.
//!   `NCryptCreatePersistedKey` is the exception, and does not accept it — see the
//!   comment at that call.
//!
//! Keys are *persisted* under a name derived from Keystone's key ID rather than
//! created ephemerally, because a TPM key handle does not survive the process and
//! the CLI signs in a later invocation than the one that generated the key. The
//! name is the handle Keystone stores; unlike CryptoKit's data representation
//! there is no blob to keep, and the private key never leaves the TPM.

use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
    BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
    NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

use crate::{wide, Result, Win32Error};

// The status values are re-exported from `windows-sys` rather than written out as
// decimals. A `SECURITY_STATUS` typo is a bug that only appears on real hardware,
// as an error taking the wrong branch, and nothing on a development machine would
// catch it.

/// `NTE_BAD_KEYSET` (0x80090016): the named key does not exist. Also what opening
/// the Platform Crypto Provider returns on a machine whose TPM is absent or not
/// owned, since the provider's key container itself is then missing.
pub use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
/// `NTE_DEVICE_NOT_READY` (0x80090030): the TPM is present but not usable —
/// disabled in firmware, not yet provisioned, or in a failed state.
pub use windows_sys::Win32::Foundation::NTE_DEVICE_NOT_READY;
/// `NTE_EXISTS` (0x8009000F): a key of that name is already present.
pub use windows_sys::Win32::Foundation::NTE_EXISTS;
/// `NTE_INVALID_PARAMETER` (0x80090027): used here to report that a blob CNG
/// returned is not the shape this crate requires. Distinct from
/// [`NTE_NOT_SUPPORTED`], which means the provider refused the operation.
pub use windows_sys::Win32::Foundation::NTE_INVALID_PARAMETER;
/// `NTE_NOT_SUPPORTED` (0x80090029): the provider cannot do what was asked.
pub use windows_sys::Win32::Foundation::NTE_NOT_SUPPORTED;

/// Whether a CNG status means "this machine has no usable TPM".
///
/// Shared so the availability probe and the backend's error mapping cannot drift
/// apart: a status one treats as "no TPM" and the other treats as a hard failure
/// produces a `doctor` that reports healthy and a `bootstrap` that fails, or the
/// reverse.
pub fn means_no_tpm(code: i32) -> bool {
    matches!(
        code,
        NTE_NOT_SUPPORTED | NTE_BAD_KEYSET | NTE_DEVICE_NOT_READY
    )
}

/// An open handle to the Platform Crypto Provider.
///
/// Closed on drop. Held separately from a key because `NCryptOpenKey` needs it and
/// because opening it is the availability probe.
pub struct Provider {
    handle: NCRYPT_PROV_HANDLE,
}

impl Provider {
    /// Open the TPM-backed provider.
    ///
    /// Fails on a machine with no TPM, which is what makes this the availability
    /// check. The software provider is deliberately not attempted as a fallback.
    pub fn open_platform() -> Result<Self> {
        let mut handle: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: `handle` is a valid out-pointer for the duration of the call.
        // `MS_PLATFORM_CRYPTO_PROVIDER` is a static NUL-terminated wide string
        // from `windows-sys`. On a non-zero return the handle is not written and
        // is not used.
        #[allow(unsafe_code)]
        let status =
            unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        if status != 0 {
            return Err(Win32Error::new("NCryptOpenStorageProvider", status));
        }
        Ok(Self { handle })
    }

    fn raw(&self) -> NCRYPT_PROV_HANDLE {
        self.handle
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: `handle` came from a successful `NCryptOpenStorageProvider`
            // and is freed exactly once, here. The failure status is ignored
            // because a drop cannot report and there is no recovery.
            #[allow(unsafe_code)]
            unsafe {
                NCryptFreeObject(self.handle);
            }
        }
    }
}

/// A persisted P-256 signing key living in the TPM.
///
/// The handle is closed on drop; the key itself persists under its name until
/// [`delete`](Self::delete) removes it.
pub struct TpmKey {
    handle: NCRYPT_KEY_HANDLE,
}

impl TpmKey {
    /// Create a new non-exportable P-256 signing key named `name`.
    ///
    /// Returns [`NTE_EXISTS`] if the name is taken. The caller decides whether
    /// that is an error or a reason to open the existing key; this layer does not
    /// overwrite, because silently replacing a key would destroy the private key a
    /// certificate still names.
    pub fn create(provider: &Provider, name: &str) -> Result<Self> {
        let name_w = wide(name);
        let mut handle: NCRYPT_KEY_HANDLE = 0;
        // The final flags argument is `0`, not `NCRYPT_SILENT_FLAG`. This call's
        // documented flags are the machine-key and overwrite flags; silent is not
        // among them, and CNG rejects undocumented flags on some providers. There is
        // nothing to suppress here in any case — no UI can appear before the key
        // exists. Silence is enforced where it can be: on `NCryptFinalizeKey`, which
        // is where the TPM is actually engaged, and on every operation afterwards.
        //
        // Neither is `NCRYPT_OVERWRITE_KEY_FLAG` passed: an existing name must come
        // back as `NTE_EXISTS` for the caller to decide about, never be replaced,
        // since overwriting would destroy the private key a live certificate names.
        //
        // SAFETY: `provider` is a live handle, `name_w` is NUL-terminated and
        // outlives the call, and `handle` is a valid out-pointer. `0` for
        // `dwLegacyKeySpec` is required for a CNG-only key.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.raw(),
                &mut handle,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name_w.as_ptr(),
                0,
                0,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptCreatePersistedKey", status));
        }
        let key = Self { handle };

        // Order matters: both properties must be set on the unfinalized key.
        // After `NCryptFinalizeKey` the export policy is immutable, which is the
        // point — it cannot be widened later.
        key.set_u32_property(NCRYPT_EXPORT_POLICY_PROPERTY, 0)?;
        key.set_u32_property(NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG)?;

        // SAFETY: `handle` is a live unfinalized key from the call above.
        #[allow(unsafe_code)]
        let status = unsafe { NCryptFinalizeKey(key.handle, NCRYPT_SILENT_FLAG) };
        if status != 0 {
            return Err(Win32Error::new("NCryptFinalizeKey", status));
        }
        Ok(key)
    }

    /// Open an existing key by name.
    ///
    /// Returns [`NTE_BAD_KEYSET`] when no such key exists, which the backend maps
    /// to Keystone's "key unavailable" rather than a generic failure.
    pub fn open(provider: &Provider, name: &str) -> Result<Self> {
        let name_w = wide(name);
        let mut handle: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: as in `create`; `name_w` outlives the call.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptOpenKey(
                provider.raw(),
                &mut handle,
                name_w.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptOpenKey", status));
        }
        Ok(Self { handle })
    }

    fn set_u32_property(&self, property: windows_sys::core::PCWSTR, value: u32) -> Result<()> {
        let bytes = value.to_ne_bytes();
        // SAFETY: `self.handle` is live; `bytes` is a 4-byte buffer whose length
        // is passed as `cbinput`, and it outlives the call.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptSetProperty(
                self.handle,
                property,
                bytes.as_ptr(),
                bytes.len() as u32,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptSetProperty", status));
        }
        Ok(())
    }

    /// Export the public key as 65-byte uncompressed SEC1 (`0x04 || X || Y`).
    ///
    /// CNG hands back a `BCRYPT_ECCKEY_BLOB` header followed by X and Y as
    /// fixed-width big-endian integers, *without* the `0x04` prefix. The
    /// conversion is here so that only this module knows CNG's layout, and the
    /// magic value is checked so a provider returning some other curve cannot be
    /// silently reinterpreted as P-256.
    pub fn public_key_sec1(&self) -> Result<[u8; 65]> {
        let mut needed: u32 = 0;
        // SAFETY: a null output buffer with zero length is the documented way to
        // ask for the required size; `needed` is a valid out-pointer.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptExportKey(
                self.handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptExportKey", status));
        }

        let header = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
        let mut buffer = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: `buffer` is `needed` bytes long and that same length is passed
        // as `cboutput`, so the provider cannot write past the end.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptExportKey(
                self.handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                needed,
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptExportKey", status));
        }
        buffer.truncate(written as usize);

        // The three checks below report `NTE_INVALID_PARAMETER`, not
        // `NTE_NOT_SUPPORTED`: the provider answered successfully and the blob it
        // returned is wrong. Reusing the no-TPM status here would make a malformed
        // export indistinguishable from a machine without a TPM, and `doctor` would
        // report "no TPM" on a machine that has one.
        if buffer.len() < header {
            return Err(Win32Error::new("NCryptExportKey", NTE_INVALID_PARAMETER));
        }
        // Read the two header fields without transmuting: the blob is a byte
        // buffer from a foreign API, and `from_ne_bytes` on a copied slice needs
        // no alignment assumption.
        let magic = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        let cb_key = u32::from_ne_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;
        if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || cb_key != 32 {
            // Not a P-256 public key. Rejected rather than parsed, because
            // reinterpreting another curve's coordinates as P-256 would produce a
            // plausible-looking key that cannot verify.
            return Err(Win32Error::new("NCryptExportKey", NTE_INVALID_PARAMETER));
        }
        if buffer.len() < header + 64 {
            return Err(Win32Error::new("NCryptExportKey", NTE_INVALID_PARAMETER));
        }

        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(&buffer[header..header + 64]);
        Ok(sec1)
    }

    /// Sign a 32-byte SHA-256 digest, returning the raw 64-byte `r || s`.
    ///
    /// CNG signs a *digest*, not a message: unlike CryptoKit it applies no hash of
    /// its own. That is why the backend implements Keystone's prehashed signer and
    /// hashes once, explicitly. Passing a message here would sign the message
    /// bytes as though they were a digest and produce a signature AWS rejects
    /// without explaining why.
    ///
    /// `pPaddingInfo` is null and no padding flag is passed, which is what selects
    /// raw ECDSA. Padding info is the RSA form and must never be supplied here.
    pub fn sign_prehashed_sha256(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let mut needed: u32 = 0;
        // SAFETY: null output buffer to query the size; `digest` is 32 bytes and
        // its length is passed exactly.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                std::ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut needed,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptSignHash", status));
        }

        let mut signature = vec![0u8; needed as usize];
        let mut written: u32 = 0;
        // SAFETY: `signature` is `needed` bytes and that length is passed as
        // `cbsignature`.
        #[allow(unsafe_code)]
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                std::ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                needed,
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 {
            return Err(Win32Error::new("NCryptSignHash", status));
        }
        signature.truncate(written as usize);

        // CNG returns P-256 ECDSA as the fixed-width concatenation, not DER. A
        // short or long buffer means this is not the signature form expected, and
        // padding it to length would corrupt `s`.
        let raw: [u8; 64] = signature
            .as_slice()
            .try_into()
            .map_err(|_| Win32Error::new("NCryptSignHash", NTE_INVALID_PARAMETER))?;
        Ok(raw)
    }

    /// Delete the persisted key.
    ///
    /// Consumes the handle: `NCryptDeleteKey` frees it, so keeping it would leave a
    /// dangling handle that `Drop` would free a second time.
    pub fn delete(self) -> Result<()> {
        let handle = self.handle;
        // Do not run the destructor: the delete below releases the handle.
        std::mem::forget(self);
        // SAFETY: `handle` is live and is released exactly once, by this call.
        #[allow(unsafe_code)]
        let status = unsafe { NCryptDeleteKey(handle, NCRYPT_SILENT_FLAG) };
        if status != 0 {
            return Err(Win32Error::new("NCryptDeleteKey", status));
        }
        Ok(())
    }
}

impl Drop for TpmKey {
    fn drop(&mut self) {
        if self.handle != 0 {
            // SAFETY: `handle` came from `create` or `open` and is freed exactly
            // once. `delete` forgets `self` so it cannot also reach here.
            #[allow(unsafe_code)]
            unsafe {
                NCryptFreeObject(self.handle);
            }
        }
    }
}

/// Whether this machine has a usable TPM-backed provider.
///
/// Distinguishes "no TPM" from "the call failed for another reason": the first is
/// a diagnosis `keystone doctor` reports, the second is an error worth surfacing.
pub fn platform_provider_available() -> std::result::Result<bool, Win32Error> {
    match Provider::open_platform() {
        Ok(_) => Ok(true),
        Err(error) if means_no_tpm(error.code) => Ok(false),
        Err(error) => Err(error),
    }
}
