//! Reusable CA construction over an external rcgen signing key.
//!
//! This module knows certificate and CSR policy, but nothing about AWS. The
//! caller supplies a [`SigningKey`], which can be backed by KMS or a local test
//! key. No private CA material crosses this API.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use rcgen::{
    CertificateSigningRequestParams, IsCa, Issuer, KeyUsagePurpose, PublicKeyData, SanType,
    SigningKey,
};
use time::OffsetDateTime;

use crate::certificate::ParsedCertificate;
use crate::params::{random_serial, validate_name, ExternalCaSpec, DEVICE_OU};
use crate::validate::{self, ValidationContext};

const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_OID: &str = "1.2.840.10045.3.1.7";

/// Create and fully validate a self-signed reusable CA certificate.
pub fn initialize_ca(
    signer: &impl SigningKey,
    spec: &ExternalCaSpec,
    now: OffsetDateTime,
) -> Result<ParsedCertificate> {
    require_p256_signer(signer)?;
    let params = spec.to_params()?;
    let certificate = params
        .self_signed(signer)
        .map_err(|e| map_signing_error("cannot create CA certificate", e))?;
    let certificate = ParsedCertificate::from_der(certificate.der())?;
    validate::validate_reusable_ca_certificate(&certificate, now)?;
    if certificate.public_key_sec1.as_slice() != signer.der_bytes() {
        return Err(KeystoneError::CertificateKeyMismatch);
    }
    validate::validate_self_signed_ca(&certificate)?;
    Ok(certificate)
}

/// Validate a Keystone CSR and issue a constrained end-entity certificate.
pub fn issue_certificate(
    signer: &impl SigningKey,
    ca: &ParsedCertificate,
    csr_der: &[u8],
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<ParsedCertificate> {
    require_p256_signer(signer)?;
    validate::validate_reusable_ca_certificate(ca, not_before)?;
    validate::validate_self_signed_ca(ca)?;
    if ca.public_key_sec1.as_slice() != signer.der_bytes() {
        return Err(KeystoneError::CertificateKeyMismatch);
    }
    if not_after > ca.not_after {
        return Err(KeystoneError::InvalidConfiguration(
            "device certificate cannot outlive the CA certificate".to_string(),
        ));
    }
    if not_after <= not_before {
        return Err(KeystoneError::InvalidConfiguration(
            "certificate validity must end after it begins".to_string(),
        ));
    }

    let policy = validate_csr(csr_der)?;
    let csr_der = rustls_pki_types::CertificateSigningRequestDer::from(csr_der);
    let mut request = CertificateSigningRequestParams::from_der(&csr_der).map_err(|e| {
        KeystoneError::InvalidCertificate(format!("cannot parse or verify CSR: {e}"))
    })?;

    // Rebuild every extension rather than copying the request wholesale.
    request.params.not_before = not_before;
    request.params.not_after = not_after;
    request.params.serial_number = Some(random_serial());
    request.params.is_ca = IsCa::ExplicitNoCa;
    request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    request.params.extended_key_usages.clear();
    request.params.name_constraints = None;
    request.params.crl_distribution_points.clear();
    request.params.custom_extensions.clear();
    request.params.subject_alt_names =
        vec![SanType::URI(policy.uri.try_into().map_err(|e| {
            KeystoneError::InvalidCertificate(format!("CSR URI SAN is invalid: {e}"))
        })?)];
    request.params.use_authority_key_identifier_extension = true;

    let issuer = Issuer::from_ca_cert_der(&ca.der().into(), signer).map_err(|e| {
        KeystoneError::InvalidCertificateChain(format!("cannot use CA certificate: {e}"))
    })?;
    let certificate = request
        .signed_by(&issuer)
        .map_err(|e| map_signing_error("cannot issue device certificate", e))?;
    let certificate = ParsedCertificate::from_der(certificate.der())?;
    validate::validate_device_certificate(
        &certificate,
        &ValidationContext::new(not_before)
            .expecting_key(policy.public_key)
            .expecting_key_id(policy.key_id),
    )?;
    validate_issued_artifact(&certificate, ca)?;
    validate::validate_chain(&certificate, &[], ca, not_before)?;
    Ok(certificate)
}

fn require_p256_signer(signer: &impl PublicKeyData) -> Result<()> {
    if signer.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 || signer.der_bytes().len() != 65 {
        return Err(KeystoneError::InvalidConfiguration(
            "external CA signer must use ECDSA P-256 with SHA-256".to_string(),
        ));
    }
    p256::PublicKey::from_sec1_bytes(signer.der_bytes()).map_err(|e| {
        KeystoneError::InvalidConfiguration(format!("external CA public key is invalid: {e}"))
    })?;
    Ok(())
}

#[derive(Debug)]
struct CsrPolicy {
    public_key: [u8; 65],
    uri: String,
    key_id: KeyId,
}

fn validate_csr(der: &[u8]) -> Result<CsrPolicy> {
    use x509_parser::cri_attributes::ParsedCriAttribute;
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::prelude::FromDer as _;

    let (rest, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(der)
            .map_err(|e| KeystoneError::InvalidCertificate(format!("cannot parse CSR: {e}")))?;
    if !rest.is_empty() {
        return Err(KeystoneError::InvalidCertificate(format!(
            "{} trailing bytes after CSR",
            rest.len()
        )));
    }
    csr.verify_signature().map_err(|e| {
        KeystoneError::InvalidCertificate(format!("CSR self-signature is invalid: {e}"))
    })?;
    if csr.signature_algorithm.algorithm.to_id_string() != ECDSA_SHA256_OID
        || csr.signature_algorithm.parameters.is_some()
    {
        return Err(KeystoneError::InvalidCertificate(
            "CSR signature algorithm must be ECDSA with SHA-256 and omit parameters".to_string(),
        ));
    }
    let spki = &csr.certification_request_info.subject_pki;
    if spki.algorithm.algorithm.to_id_string() != EC_PUBLIC_KEY_OID
        || spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .is_none_or(|oid| oid.to_id_string() != P256_OID)
    {
        return Err(KeystoneError::InvalidCertificate(
            "CSR public key must be P-256".to_string(),
        ));
    }
    let public_key: [u8; 65] =
        spki.subject_public_key.as_ref().try_into().map_err(|_| {
            KeystoneError::InvalidCertificate("CSR P-256 key is malformed".to_string())
        })?;
    p256::PublicKey::from_sec1_bytes(&public_key)
        .map_err(|e| KeystoneError::InvalidCertificate(format!("CSR P-256 key is invalid: {e}")))?;

    validate_device_subject(&csr.certification_request_info.subject)?;

    let mut uri = None;
    let mut saw_extension_request = false;
    let mut saw_san = false;
    let mut saw_key_usage = false;
    let mut saw_basic_constraints = false;
    for attribute in csr.certification_request_info.attributes() {
        match attribute.parsed_attribute() {
            ParsedCriAttribute::ExtensionRequest(request) if !saw_extension_request => {
                saw_extension_request = true;
                for extension in &request.extensions {
                    match extension.parsed_extension() {
                        ParsedExtension::SubjectAlternativeName(san) => {
                            if saw_san {
                                return Err(KeystoneError::InvalidCertificate(
                                    "CSR contains duplicate subjectAltName extensions".to_string(),
                                ));
                            }
                            saw_san = true;
                            for name in &san.general_names {
                                match name {
                                    GeneralName::URI(value) if uri.is_none() => {
                                        uri = Some((*value).to_string());
                                    }
                                    _ => return Err(KeystoneError::InvalidCertificate(
                                        "CSR must contain exactly one URI SAN and no other SAN types"
                                            .to_string(),
                                    )),
                                }
                            }
                        }
                        ParsedExtension::KeyUsage(usage) => {
                            if saw_key_usage {
                                return Err(KeystoneError::InvalidCertificate(
                                    "CSR contains duplicate keyUsage extensions".to_string(),
                                ));
                            }
                            saw_key_usage = true;
                            if !usage.digital_signature()
                                || usage.key_cert_sign()
                                || usage.crl_sign()
                                || usage.flags != 1
                            {
                                return Err(KeystoneError::InvalidCertificate(
                                    "CSR key usage must contain only digitalSignature".to_string(),
                                ));
                            }
                        }
                        ParsedExtension::BasicConstraints(constraints)
                            if !constraints.ca && constraints.path_len_constraint.is_none() =>
                        {
                            if saw_basic_constraints {
                                return Err(KeystoneError::InvalidCertificate(
                                    "CSR contains duplicate basicConstraints extensions"
                                        .to_string(),
                                ));
                            }
                            saw_basic_constraints = true;
                        }
                        ParsedExtension::BasicConstraints(_) => {
                            return Err(KeystoneError::InvalidCertificate(
                                "CSR requests CA capabilities".to_string(),
                            ));
                        }
                        _ => {
                            return Err(KeystoneError::InvalidCertificate(format!(
                                "CSR requests unsupported extension {}",
                                extension.oid
                            )))
                        }
                    }
                }
            }
            _ => {
                return Err(KeystoneError::InvalidCertificate(
                    "CSR contains an unsupported or duplicate attribute".to_string(),
                ))
            }
        }
    }
    if !saw_san || !saw_key_usage || !saw_basic_constraints {
        return Err(KeystoneError::InvalidCertificate(
            "CSR must request subjectAltName, CA=false, and digitalSignature".to_string(),
        ));
    }
    let uri = uri.ok_or(KeystoneError::MissingDeviceSan)?;
    let key_id = KeyId::from_device_san_uri(&uri).ok_or_else(|| {
        KeystoneError::InvalidCertificate(
            "CSR URI SAN must be urn:keystone:device:<valid-key-id>".to_string(),
        )
    })?;
    Ok(CsrPolicy {
        public_key,
        uri,
        key_id,
    })
}

fn validate_issued_artifact(certificate: &ParsedCertificate, ca: &ParsedCertificate) -> Result<()> {
    if !certificate.basic_constraints_critical
        || !certificate.key_usage_critical
        || certificate.key_usage_flags != 1
    {
        return Err(KeystoneError::InvalidCertificate(
            "issued certificate must have critical CA=false and only digitalSignature key usage"
                .to_string(),
        ));
    }
    if certificate.signature_algorithm_oid != ECDSA_SHA256_OID
        || certificate.signature_algorithm_parameters_present
        || certificate.uri_sans.len() != 1
        || !certificate.dns_sans.is_empty()
        || certificate.other_san_count != 0
    {
        return Err(KeystoneError::InvalidCertificate(
            "issued certificate has an unexpected signature algorithm or SAN".to_string(),
        ));
    }
    const EXPECTED_EXTENSIONS: [&str; 5] = [
        "2.5.29.14",
        "2.5.29.15",
        "2.5.29.17",
        "2.5.29.19",
        "2.5.29.35",
    ];
    if certificate.extension_oids.len() != EXPECTED_EXTENSIONS.len()
        || !EXPECTED_EXTENSIONS
            .iter()
            .all(|oid| certificate.extension_oids.iter().any(|found| found == oid))
    {
        return Err(KeystoneError::InvalidCertificate(format!(
            "issued certificate contains unexpected or missing extensions: {:?}",
            certificate.extension_oids
        )));
    }
    if certificate.authority_key_identifier.as_ref() != ca.subject_key_identifier.as_ref() {
        return Err(KeystoneError::InvalidCertificate(
            "issued certificate authority key identifier does not match the CA".to_string(),
        ));
    }
    Ok(())
}

fn validate_device_subject(subject: &x509_parser::x509::X509Name<'_>) -> Result<()> {
    let mut cn = false;
    let mut ou = false;
    let mut organization = false;
    for rdn in subject.iter() {
        let mut attributes = rdn.iter();
        let attribute = attributes.next().ok_or_else(|| {
            KeystoneError::InvalidCertificate("CSR subject contains an empty RDN".to_string())
        })?;
        if attributes.next().is_some() {
            return Err(KeystoneError::InvalidCertificate(
                "CSR subject contains a multi-valued RDN".to_string(),
            ));
        }
        let value = attribute.as_str().map_err(|_| {
            KeystoneError::InvalidCertificate("CSR subject value is not text".to_string())
        })?;
        validate_name("CSR subject value", value)?;
        match attribute.attr_type().to_id_string().as_str() {
            "2.5.4.3" if !cn => cn = true,
            "2.5.4.11" if !ou && value == DEVICE_OU => ou = true,
            "2.5.4.10" if !organization => organization = true,
            _ => {
                return Err(KeystoneError::InvalidCertificate(
                    "CSR subject must contain one CN, OU=Keystone Devices, and optional O"
                        .to_string(),
                ))
            }
        }
    }
    if !cn || !ou {
        return Err(KeystoneError::InvalidCertificate(
            "CSR subject must contain one CN and OU=Keystone Devices".to_string(),
        ));
    }
    Ok(())
}

fn map_signing_error(context: &str, error: rcgen::Error) -> KeystoneError {
    if error == rcgen::Error::RemoteKeyError {
        KeystoneError::Other(format!("{context}: external signing operation failed"))
    } else {
        KeystoneError::Other(format!("{context}: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, TEST_NOW};
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, KeyPair,
        SignatureAlgorithm,
    };

    fn ca_key() -> KeyPair {
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
    }

    fn ca(key: &KeyPair) -> ParsedCertificate {
        let spec = ExternalCaSpec::from_subject("CN=Keystone KMS CA,O=Example", TEST_NOW)
            .unwrap()
            .with_validity(TEST_NOW, TEST_NOW + time::Duration::days(3650));
        initialize_ca(key, &spec, TEST_NOW).unwrap()
    }

    fn valid_csr() -> (Vec<u8>, [u8; 65], KeyId) {
        let device = testing::random_device_key();
        let key_id = device.key_id().clone();
        let spec = crate::DeviceCertificateSpec::new("alice-laptop", key_id.clone(), TEST_NOW);
        let request = crate::create_signing_request(&device, &spec).unwrap();
        (request.der().to_vec(), device.public_key_sec1(), key_id)
    }

    fn custom_csr(
        mut params: CertificateParams,
        algorithm: &'static SignatureAlgorithm,
    ) -> Vec<u8> {
        let key = KeyPair::generate_for(algorithm).unwrap();
        let mut subject = DistinguishedName::new();
        subject.push(DnType::CommonName, "alice-laptop");
        subject.push(DnType::OrganizationalUnitName, DEVICE_OU);
        params.distinguished_name = subject;
        params.serialize_request(&key).unwrap().der().to_vec()
    }

    #[test]
    fn initialized_ca_has_the_required_semantics_and_self_signature() {
        use x509_parser::extensions::ParsedExtension;
        use x509_parser::prelude::FromDer as _;

        let key = ca_key();
        let certificate = ca(&key);
        assert_eq!(certificate.public_key_sec1.as_slice(), key.der_bytes());
        assert!(certificate.is_ca);
        assert!(certificate.basic_constraints_critical);
        assert_eq!(certificate.path_len, Some(0));
        assert_eq!(certificate.key_usage_flags, 1 << 5 | 1 << 6);
        assert_eq!(
            (certificate.not_after - certificate.not_before).whole_days(),
            3650
        );
        validate::validate_self_signed_ca(&certificate).unwrap();

        let (_, parsed) =
            x509_parser::certificate::X509Certificate::from_der(certificate.der()).unwrap();
        assert_eq!(
            parsed.signature_algorithm.algorithm.to_id_string(),
            ECDSA_SHA256_OID
        );
        assert!(parsed.extensions().iter().any(|extension| matches!(
            extension.parsed_extension(),
            ParsedExtension::SubjectKeyIdentifier(_)
        )));
    }

    #[test]
    fn reinitializing_a_ca_uses_a_fresh_random_serial() {
        let key = ca_key();
        let first = ca(&key);
        let second = ca(&key);
        assert_ne!(first.serial_decimal, second.serial_decimal);
    }

    #[test]
    fn unexpected_and_duplicate_certificate_extensions_fail_closed() {
        let key = ca_key();
        let spec = ExternalCaSpec::from_subject("CN=Keystone KMS CA", TEST_NOW).unwrap();
        let mut params = spec.to_params().unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55_555, 1],
                vec![0x05, 0x00],
            ));
        let certificate = params.self_signed(&key).unwrap();
        let parsed = ParsedCertificate::from_der(certificate.der()).unwrap();
        assert!(validate::validate_reusable_ca_certificate(&parsed, TEST_NOW).is_err());

        let mut duplicate = CertificateParams::default();
        duplicate.is_ca = IsCa::ExplicitNoCa;
        let mut basic_constraints =
            CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x00]);
        basic_constraints.set_criticality(true);
        duplicate.custom_extensions.push(basic_constraints);
        let certificate = duplicate.self_signed(&key).unwrap();
        assert!(ParsedCertificate::from_der(certificate.der()).is_err());
    }

    #[test]
    fn malformed_ca_subjects_are_rejected() {
        for subject in [
            "O=Example",
            "CN=",
            "CN=bad\nname",
            "CN=one,CN=two",
            "C=US,CN=Example",
            "CN",
            "CN=foo+OU=bar",
            "CN=foo=bar",
        ] {
            assert!(
                ExternalCaSpec::from_subject(subject, TEST_NOW).is_err(),
                "accepted {subject:?}"
            );
        }
    }

    #[test]
    fn valid_keystone_csr_issues_a_valid_leaf_with_matching_key_and_san() {
        use x509_parser::extensions::ParsedExtension;
        use x509_parser::prelude::FromDer as _;

        let ca_key = ca_key();
        let ca = ca(&ca_key);
        let (csr, public_key, key_id) = valid_csr();
        let leaf = issue_certificate(
            &ca_key,
            &ca,
            &csr,
            TEST_NOW,
            TEST_NOW + time::Duration::days(365),
        )
        .unwrap();
        assert_eq!(leaf.public_key_sec1, public_key);
        assert_eq!(leaf.uri_sans, vec![key_id.device_san_uri()]);
        assert!(!leaf.is_ca);
        assert!(leaf.basic_constraints_critical);
        assert_eq!(leaf.key_usage_flags, 1);
        assert!(leaf.key_usage_critical);
        validate::validate_chain(&leaf, &[], &ca, TEST_NOW).unwrap();

        let (_, ca_x509) = x509_parser::certificate::X509Certificate::from_der(ca.der()).unwrap();
        let (_, leaf_x509) =
            x509_parser::certificate::X509Certificate::from_der(leaf.der()).unwrap();
        let ski = ca_x509
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0),
                _ => None,
            })
            .unwrap();
        let aki = leaf_x509
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(id) => id.key_identifier.clone(),
                _ => None,
            })
            .unwrap();
        assert_eq!(aki.0, ski);
    }

    #[test]
    fn corrupt_csr_is_rejected() {
        let ca_key = ca_key();
        let ca = ca(&ca_key);
        let (mut csr, _, _) = valid_csr();
        let index = csr.len() / 2;
        csr[index] ^= 1;
        assert!(issue_certificate(
            &ca_key,
            &ca,
            &csr,
            TEST_NOW,
            TEST_NOW + time::Duration::days(365)
        )
        .is_err());
    }

    #[test]
    fn leaf_cannot_outlive_ca() {
        let ca_key = ca_key();
        let ca = ca(&ca_key);
        let (csr, _, _) = valid_csr();
        let error = issue_certificate(
            &ca_key,
            &ca,
            &csr,
            TEST_NOW,
            ca.not_after + time::Duration::seconds(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("outlive"), "{error}");
    }

    #[test]
    fn csr_with_unsupported_key_algorithm_is_rejected() {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(
            "urn:keystone:device:019cabc".try_into().unwrap(),
        )];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.is_ca = IsCa::ExplicitNoCa;
        let csr = custom_csr(params, &rcgen::PKCS_ECDSA_P384_SHA384);
        let error = validate_csr(&csr).unwrap_err();
        assert!(error.to_string().contains("signature algorithm"), "{error}");
    }

    #[test]
    fn missing_or_unexpected_sans_are_rejected() {
        let mut missing = CertificateParams::default();
        missing.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        missing.is_ca = IsCa::ExplicitNoCa;
        let error = validate_csr(&custom_csr(missing, &rcgen::PKCS_ECDSA_P256_SHA256)).unwrap_err();
        assert!(error.to_string().contains("must request"), "{error}");

        let mut unexpected = CertificateParams::default();
        unexpected.subject_alt_names = vec![SanType::DnsName("example.test".try_into().unwrap())];
        unexpected.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        unexpected.is_ca = IsCa::ExplicitNoCa;
        let error =
            validate_csr(&custom_csr(unexpected, &rcgen::PKCS_ECDSA_P256_SHA256)).unwrap_err();
        assert!(error.to_string().contains("exactly one URI SAN"), "{error}");

        let mut multiple = CertificateParams::default();
        multiple.subject_alt_names = vec![
            SanType::URI("urn:keystone:device:019cabc".try_into().unwrap()),
            SanType::URI("urn:keystone:device:019cdef".try_into().unwrap()),
        ];
        multiple.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        multiple.is_ca = IsCa::ExplicitNoCa;
        let error =
            validate_csr(&custom_csr(multiple, &rcgen::PKCS_ECDSA_P256_SHA256)).unwrap_err();
        assert!(error.to_string().contains("exactly one URI SAN"), "{error}");

        let mut malformed = CertificateParams::default();
        malformed.subject_alt_names =
            vec![SanType::URI("urn:keystone:device:bad!".try_into().unwrap())];
        malformed.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        malformed.is_ca = IsCa::ExplicitNoCa;
        let error =
            validate_csr(&custom_csr(malformed, &rcgen::PKCS_ECDSA_P256_SHA256)).unwrap_err();
        assert!(
            error.to_string().contains("must be urn:keystone:device"),
            "{error}"
        );
    }

    #[test]
    fn requests_for_ca_capabilities_are_rejected() {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(
            "urn:keystone:device:019cabc".try_into().unwrap(),
        )];
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let error = validate_csr(&custom_csr(params, &rcgen::PKCS_ECDSA_P256_SHA256)).unwrap_err();
        assert!(error.to_string().contains("key usage"), "{error}");

        let mut path_len = CertificateParams::default();
        path_len.subject_alt_names = vec![SanType::URI(
            "urn:keystone:device:019cabc".try_into().unwrap(),
        )];
        path_len.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        path_len.is_ca = IsCa::NoCa;
        let mut basic_constraints =
            CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x03, 0x02, 0x01, 0]);
        basic_constraints.set_criticality(true);
        path_len.custom_extensions.push(basic_constraints);
        let error =
            validate_csr(&custom_csr(path_len, &rcgen::PKCS_ECDSA_P256_SHA256)).unwrap_err();
        assert!(error.to_string().contains("CA capabilities"), "{error}");
    }

    #[test]
    fn signer_must_match_ca_certificate() {
        let first = ca_key();
        let ca = ca(&first);
        let second = ca_key();
        let (csr, _, _) = valid_csr();
        assert!(matches!(
            issue_certificate(
                &second,
                &ca,
                &csr,
                TEST_NOW,
                TEST_NOW + time::Duration::days(365)
            ),
            Err(KeystoneError::CertificateKeyMismatch)
        ));
    }
}
