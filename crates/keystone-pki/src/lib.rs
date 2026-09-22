//! X.509 for Keystone: certificate construction, the one-shot CA, and validation.
//!
//! The crate deals only in public material. The only private key it ever holds is
//! the ephemeral CA key in [`ephemeral_ca`], which never leaves that module's
//! `issue` call; the device key stays in the machine's secure hardware and reaches
//! this crate through [`keystone_core::signer::KeystoneSigningIdentity`].

pub mod certificate;
pub mod csr;
pub mod ephemeral_ca;
pub mod external_ca;
pub mod params;
pub mod signature;
pub mod validate;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use certificate::ParsedCertificate;
pub use csr::{create_signing_request, CertificateRequest};
pub use ephemeral_ca::{verify_device_signature, EphemeralCaOutput};
pub use external_ca::{initialize_ca, issue_certificate};
pub use params::{DeviceCertificateSpec, EphemeralCaSpec, ExternalCaSpec};
pub use signature::{der_to_raw, raw_to_der, verify_der_signature};
pub use validate::{
    validate_ca_certificate, validate_chain, validate_device_certificate,
    validate_reusable_ca_certificate, validate_self_signed_ca, ValidationContext,
};
