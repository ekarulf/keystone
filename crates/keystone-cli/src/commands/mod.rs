//! One module per command.
//!
//! Each exposes a single `run` taking the [`Context`](crate::context::Context)
//! and its own parsed arguments, so `main` is only a dispatch table and the
//! commands share no mutable state.

use std::path::Path;

use keystone_core::error::{KeystoneError, Result};
use keystone_pki::ParsedCertificate;

pub mod bootstrap;
pub mod ca;
pub mod credential_process;
pub mod doctor;
pub mod enroll;
pub mod infra;
pub mod init;
pub mod inspect;
pub mod profiles;
pub mod revoke;
pub mod rotate;
pub mod test;

/// Read exactly one certificate, accepting PEM or DER.
pub(super) fn read_certificate(path: &Path) -> Result<ParsedCertificate> {
    let bytes = std::fs::read(path)
        .map_err(|error| KeystoneError::io(format!("cannot read {}", path.display()), error))?;
    match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
            ParsedCertificate::from_pem(text)
        }
        _ => ParsedCertificate::from_der(&bytes),
    }
}

/// Read a PEM certificate bundle, or a single DER certificate.
pub(super) fn read_certificate_bundle(path: &Path) -> Result<Vec<ParsedCertificate>> {
    let bytes = std::fs::read(path)
        .map_err(|error| KeystoneError::io(format!("cannot read {}", path.display()), error))?;
    match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
            ParsedCertificate::from_pem_bundle(text)
        }
        _ => Ok(vec![ParsedCertificate::from_der(&bytes)?]),
    }
}
