//! Certificate validation.
//!
//! These are the checks `keystone enroll install` runs before it will persist a
//! certificate, and the ones `bootstrap` runs against what it just issued. Each
//! maps to a distinct [`KeystoneError`] variant so the CLI can explain what is
//! wrong instead of reporting "invalid certificate": a certificate that AWS will
//! reject should be refused here, where the message can name the field.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use time::OffsetDateTime;

use crate::certificate::ParsedCertificate;

/// What the certificate is expected to contain.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// The time to evaluate the validity window against.
    pub now: OffsetDateTime,
    /// The Secure Enclave public key the certificate must name.
    ///
    /// `None` skips the check — used by `inspect` on a certificate whose key is
    /// not available, never by `enroll install`.
    pub expected_public_key_sec1: Option<[u8; 65]>,
    /// The key ID the URI SAN must carry.
    pub expected_key_id: Option<KeyId>,
}

impl ValidationContext {
    pub fn new(now: OffsetDateTime) -> Self {
        Self {
            now,
            expected_public_key_sec1: None,
            expected_key_id: None,
        }
    }

    pub fn expecting_key(mut self, public_key_sec1: [u8; 65]) -> Self {
        self.expected_public_key_sec1 = Some(public_key_sec1);
        self
    }

    pub fn expecting_key_id(mut self, key_id: KeyId) -> Self {
        self.expected_key_id = Some(key_id);
        self
    }
}

/// Run every device-certificate check, in the design document's order.
///
/// Steps 1 and 3 (parse, P-256 public key) happen in
/// [`ParsedCertificate::from_der`], which cannot construct a certificate that
/// fails them.
pub fn validate_device_certificate(
    certificate: &ParsedCertificate,
    context: &ValidationContext,
) -> Result<()> {
    check_version(certificate)?;
    // Before the key-usage check, so a CA certificate handed to `enroll install`
    // is described as a CA rather than as a certificate that cannot sign.
    check_not_a_ca(certificate)?;
    check_digital_signature(certificate)?;
    check_validity(certificate, context.now)?;
    if let Some(expected) = &context.expected_public_key_sec1 {
        check_public_key(certificate, expected)?;
    }
    check_device_san(certificate, context.expected_key_id.as_ref())?;
    Ok(())
}

/// Confirm X.509 version 3.
///
/// IAM Roles Anywhere requires v3, and a v1 certificate cannot carry the URI SAN
/// that Keystone's authorization depends on.
fn check_version(certificate: &ParsedCertificate) -> Result<()> {
    if certificate.version != 3 {
        return Err(KeystoneError::InvalidCertificate(format!(
            "certificate is X.509 v{}; IAM Roles Anywhere requires v3",
            certificate.version
        )));
    }
    Ok(())
}

/// Confirm `digitalSignature` key usage.
fn check_digital_signature(certificate: &ParsedCertificate) -> Result<()> {
    if !certificate.key_usage_digital_signature {
        return Err(KeystoneError::InvalidCertificate(
            "certificate does not permit digitalSignature, so it cannot sign a CreateSession request"
                .to_string(),
        ));
    }
    Ok(())
}

/// Confirm `CA=false`.
fn check_not_a_ca(certificate: &ParsedCertificate) -> Result<()> {
    if certificate.is_ca {
        return Err(KeystoneError::InvalidCertificate(
            "certificate is a CA certificate; IAM Roles Anywhere requires an end-entity certificate"
                .to_string(),
        ));
    }
    Ok(())
}

/// Confirm the certificate is currently valid.
fn check_validity(certificate: &ParsedCertificate, now: OffsetDateTime) -> Result<()> {
    if now < certificate.not_before {
        return Err(KeystoneError::CertificateNotYetValid);
    }
    if now > certificate.not_after {
        return Err(KeystoneError::CertificateExpired(certificate.not_after));
    }
    Ok(())
}

/// Confirm the public key exactly matches the Secure Enclave key.
///
/// The check that makes the rest meaningful: a certificate for someone else's
/// key would let Keystone present an identity it cannot sign for, failing later
/// with an opaque AWS rejection.
fn check_public_key(certificate: &ParsedCertificate, expected: &[u8; 65]) -> Result<()> {
    if certificate.public_key_sec1 != *expected {
        return Err(KeystoneError::CertificateKeyMismatch);
    }
    Ok(())
}

/// Confirm the expected Keystone URI SAN exists.
fn check_device_san(certificate: &ParsedCertificate, expected: Option<&KeyId>) -> Result<()> {
    let found = certificate
        .device_key_id()
        .ok_or(KeystoneError::MissingDeviceSan)?;
    if let Some(expected) = expected {
        if &found != expected {
            return Err(KeystoneError::InvalidCertificate(format!(
                "certificate names device {found}, but this profile's identity is {expected}"
            )));
        }
    }
    Ok(())
}

/// Check the constraints Keystone requires of a CA certificate it issued or is
/// about to register as a trust anchor.
pub fn validate_ca_certificate(certificate: &ParsedCertificate, now: OffsetDateTime) -> Result<()> {
    check_version(certificate)?;
    if !certificate.is_ca {
        return Err(KeystoneError::InvalidCertificateChain(
            "issuer certificate is not marked as a CA".to_string(),
        ));
    }
    if !certificate.basic_constraints_critical {
        return Err(KeystoneError::InvalidCertificateChain(
            "issuer certificate's basicConstraints extension is not critical".to_string(),
        ));
    }
    if !certificate.key_usage_key_cert_sign {
        return Err(KeystoneError::InvalidCertificateChain(
            "issuer certificate does not permit keyCertSign".to_string(),
        ));
    }
    check_validity(certificate, now).map_err(|error| match error {
        KeystoneError::CertificateExpired(when) => {
            KeystoneError::InvalidCertificateChain(format!("issuer certificate expired at {when}"))
        }
        KeystoneError::CertificateNotYetValid => KeystoneError::InvalidCertificateChain(
            "issuer certificate is not yet valid".to_string(),
        ),
        other => other,
    })?;
    Ok(())
}

/// Validate the chain from `leaf` through `intermediates` to `anchor`.
///
/// `intermediates` is in leaf-to-root order, as a PEM chain file is written.
/// Every signature is verified, not just the subject and issuer names: a chain
/// that merely looks connected would be accepted by Keystone and then rejected
/// by AWS.
pub fn validate_chain(
    leaf: &ParsedCertificate,
    intermediates: &[ParsedCertificate],
    anchor: &ParsedCertificate,
    now: OffsetDateTime,
) -> Result<()> {
    // pathLen=0 on the anchor forbids an intermediate beneath it, which is the
    // shape the ephemeral CA produces.
    if anchor.path_len == Some(0) && !intermediates.is_empty() {
        return Err(KeystoneError::InvalidCertificateChain(format!(
            "anchor has pathLen=0 but {} intermediate certificate(s) were supplied",
            intermediates.len()
        )));
    }

    for issuer in intermediates {
        validate_ca_certificate(issuer, now)?;
    }
    validate_ca_certificate(anchor, now)?;

    if !anchor.is_self_issued() {
        return Err(KeystoneError::InvalidCertificateChain(format!(
            "the trust anchor {:?} is not self-issued, so the chain does not terminate",
            anchor.subject
        )));
    }

    // Walk leaf → intermediates → anchor, verifying each link.
    let mut child = leaf;
    for issuer in intermediates.iter().chain(std::iter::once(anchor)) {
        verify_issued_by(child, issuer)?;
        child = issuer;
    }
    // The anchor signs itself, which is the last thing to confirm.
    verify_issued_by(anchor, anchor)?;
    Ok(())
}

/// Verify that `issuer` signed `child`.
fn verify_issued_by(child: &ParsedCertificate, issuer: &ParsedCertificate) -> Result<()> {
    if child.issuer != issuer.subject {
        return Err(KeystoneError::InvalidCertificateChain(format!(
            "certificate {:?} names issuer {:?}, which does not match the supplied issuer {:?}",
            child.subject, child.issuer, issuer.subject
        )));
    }

    use x509_parser::prelude::FromDer as _;
    let (_, parsed) =
        x509_parser::certificate::X509Certificate::from_der(child.der()).map_err(|e| {
            KeystoneError::InvalidCertificateChain(format!("cannot re-parse certificate: {e}"))
        })?;
    let (_, parsed_issuer) = x509_parser::certificate::X509Certificate::from_der(issuer.der())
        .map_err(|e| {
            KeystoneError::InvalidCertificateChain(format!("cannot re-parse issuer: {e}"))
        })?;

    parsed
        .verify_signature(Some(parsed_issuer.public_key()))
        .map_err(|e| {
            KeystoneError::InvalidCertificateChain(format!(
                "certificate {:?} was not signed by {:?}: {e}",
                child.subject, issuer.subject
            ))
        })
}

/// Describe how much of a certificate's life is left, for `inspect` and `doctor`.
pub fn expiry_warning(
    certificate: &ParsedCertificate,
    now: OffsetDateTime,
    warn_within: time::Duration,
) -> Option<String> {
    let remaining = certificate.remaining(now);
    if remaining.is_negative() {
        return Some(format!(
            "certificate expired {}",
            keystone_core::time::describe_duration_days(-remaining)
        ));
    }
    if remaining <= warn_within {
        return Some(format!(
            "certificate expires in {}",
            keystone_core::time::describe_duration_days(remaining)
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, TestCa};

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn context(bundle: &testing::DeviceBundle) -> ValidationContext {
        ValidationContext::new(NOW)
            .expecting_key(bundle.device_public_key)
            .expecting_key_id(bundle.key_id.clone())
    }

    #[test]
    fn a_well_formed_device_certificate_passes_every_check() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        validate_device_certificate(&leaf, &context(&bundle)).unwrap();
    }

    #[test]
    fn a_certificate_for_another_key_is_refused() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();

        let mut context = context(&bundle);
        context.expected_public_key_sec1 = Some(testing::random_device_key().public_key_sec1());
        assert!(matches!(
            validate_device_certificate(&leaf, &context),
            Err(KeystoneError::CertificateKeyMismatch)
        ));
    }

    #[test]
    fn a_certificate_for_another_device_id_is_refused() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();

        let mut context = context(&bundle);
        context.expected_key_id = Some(KeyId::generate());
        let error = validate_device_certificate(&leaf, &context).unwrap_err();
        assert!(error.to_string().contains("names device"), "{error}");
    }

    #[test]
    fn a_certificate_without_a_device_san_is_refused() {
        let ca = TestCa::generate();
        let key = testing::random_device_key();
        let der = ca.issue_certificate_with_uri_san(&key, "example-laptop", None);
        let leaf = ParsedCertificate::from_der(&der).unwrap();

        assert!(matches!(
            validate_device_certificate(&leaf, &ValidationContext::new(NOW)),
            Err(KeystoneError::MissingDeviceSan)
        ));
    }

    #[test]
    fn a_certificate_with_someone_elses_uri_san_is_refused() {
        let ca = TestCa::generate();
        let key = testing::random_device_key();
        let der =
            ca.issue_certificate_with_uri_san(&key, "example-laptop", Some("urn:example:device:1"));
        let leaf = ParsedCertificate::from_der(&der).unwrap();
        assert!(matches!(
            validate_device_certificate(&leaf, &ValidationContext::new(NOW)),
            Err(KeystoneError::MissingDeviceSan)
        ));
    }

    #[test]
    fn an_expired_certificate_is_refused_and_names_its_expiry() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();

        let mut context = context(&bundle);
        context.now = leaf.not_after + time::Duration::seconds(1);
        match validate_device_certificate(&leaf, &context) {
            Err(KeystoneError::CertificateExpired(when)) => assert_eq!(when, leaf.not_after),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn a_certificate_from_the_future_is_refused() {
        // A clock that is wrong in the other direction, or a certificate issued
        // for later use.
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();

        let mut context = context(&bundle);
        context.now = leaf.not_before - time::Duration::seconds(1);
        assert!(matches!(
            validate_device_certificate(&leaf, &context),
            Err(KeystoneError::CertificateNotYetValid)
        ));
    }

    #[test]
    fn a_ca_certificate_is_refused_as_a_device_certificate() {
        let bundle = testing::device_bundle();
        let ca = ParsedCertificate::from_der(bundle.ca_der()).unwrap();

        let error = validate_device_certificate(&ca, &ValidationContext::new(NOW)).unwrap_err();
        assert!(error.to_string().contains("end-entity"), "{error}");
    }

    #[test]
    fn a_certificate_without_digital_signature_usage_is_refused() {
        let ca = TestCa::generate();
        let key = testing::random_device_key();
        let der = ca.issue_certificate_without_digital_signature(&key, &KeyId::generate());
        let leaf = ParsedCertificate::from_der(&der).unwrap();

        let error = validate_device_certificate(&leaf, &ValidationContext::new(NOW)).unwrap_err();
        assert!(error.to_string().contains("digitalSignature"), "{error}");
    }

    #[test]
    fn a_chain_from_the_leaf_to_its_own_ca_validates() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let anchor = ParsedCertificate::from_der(bundle.ca_der()).unwrap();
        validate_chain(&leaf, &[], &anchor, NOW).unwrap();
    }

    #[test]
    fn a_chain_to_an_unrelated_ca_is_refused() {
        // The failure mode this exists for: a chain file from a different
        // bootstrap, which would be registered as a trust anchor that cannot
        // vouch for the device.
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let other = testing::device_bundle();
        let wrong_anchor = ParsedCertificate::from_der(other.ca_der()).unwrap();

        let error = validate_chain(&leaf, &[], &wrong_anchor, NOW).unwrap_err();
        assert!(matches!(error, KeystoneError::InvalidCertificateChain(_)));
    }

    #[test]
    fn a_chain_whose_signature_does_not_verify_is_refused() {
        // Two CAs with the same subject name: the names line up, so only a
        // signature check catches this.
        let key_id = KeyId::parse("019cabc").unwrap();
        let key = testing::random_device_key();
        let real = TestCa::with_key_id(&key_id);
        let impostor = TestCa::with_key_id(&key_id);

        let leaf_der = real.issue_device_certificate(
            &key,
            "example-laptop",
            &key_id,
            NOW - time::Duration::days(1),
            NOW + time::Duration::days(365),
        );
        let leaf = ParsedCertificate::from_der(&leaf_der).unwrap();
        let impostor_anchor = ParsedCertificate::from_der(impostor.certificate_der()).unwrap();
        assert_eq!(leaf.issuer, impostor_anchor.subject);

        let error = validate_chain(&leaf, &[], &impostor_anchor, NOW).unwrap_err();
        assert!(error.to_string().contains("not signed by"), "{error}");
    }

    #[test]
    fn an_anchor_that_is_not_self_issued_is_refused() {
        // Presenting an intermediate as the anchor would register a trust anchor
        // that cannot validate its own chain.
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let error = validate_chain(&leaf, &[], &leaf, NOW).unwrap_err();
        assert!(matches!(error, KeystoneError::InvalidCertificateChain(_)));
    }

    #[test]
    fn an_intermediate_under_a_path_len_zero_anchor_is_refused() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let anchor = ParsedCertificate::from_der(bundle.ca_der()).unwrap();
        let error = validate_chain(&leaf, std::slice::from_ref(&anchor), &anchor, NOW).unwrap_err();
        assert!(error.to_string().contains("pathLen=0"), "{error}");
    }

    #[test]
    fn an_expired_anchor_is_refused_with_a_chain_error() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let anchor = ParsedCertificate::from_der(bundle.ca_der()).unwrap();

        let later = anchor.not_after + time::Duration::days(1);
        let error = validate_chain(&leaf, &[], &anchor, later).unwrap_err();
        assert!(error.to_string().contains("expired"), "{error}");
    }

    #[test]
    fn a_leaf_presented_as_its_own_anchor_is_refused() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let error = validate_ca_certificate(&leaf, NOW).unwrap_err();
        assert!(error.to_string().contains("not marked as a CA"), "{error}");
    }

    #[test]
    fn expiry_warnings_appear_only_inside_the_window() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let warn_within = time::Duration::days(30);

        assert!(expiry_warning(&leaf, NOW, warn_within).is_none());

        let inside = leaf.not_after - time::Duration::days(10);
        let warning = expiry_warning(&leaf, inside, warn_within).unwrap();
        assert!(warning.contains("expires in"), "{warning}");

        let after = leaf.not_after + time::Duration::days(3);
        let warning = expiry_warning(&leaf, after, warn_within).unwrap();
        assert!(warning.contains("expired"), "{warning}");
    }
}
