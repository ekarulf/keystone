//! Parsing and inspecting X.509 certificates.
//!
//! Keystone only ever handles P-256 end-entity certificates and their issuers,
//! so this wraps `x509-parser` in a narrow view of exactly the fields the
//! validation rules examine.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::{KeyId, Sha256Fingerprint};
use std::collections::HashSet;
use time::OffsetDateTime;
// Imported by name rather than through `x509_parser::prelude::*`, whose glob
// includes a `time` module that would shadow the `time` crate.
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer as _;

/// PEM label for a certificate.
const PEM_LABEL: &str = "CERTIFICATE";

/// A DER-encoded certificate together with the fields Keystone checks.
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    der: Vec<u8>,
    pub version: u32,
    pub serial_decimal: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub is_ca: bool,
    pub basic_constraints_critical: bool,
    pub path_len: Option<u32>,
    pub key_usage_digital_signature: bool,
    pub key_usage_key_cert_sign: bool,
    pub key_usage_crl_sign: bool,
    pub key_usage_critical: bool,
    pub key_usage_flags: u16,
    /// Present only for a P-256 key; other curves and algorithms are refused
    /// at parse time, since Keystone cannot use them.
    pub public_key_sec1: [u8; 65],
    pub uri_sans: Vec<String>,
    pub dns_sans: Vec<String>,
    pub other_san_count: usize,
    pub signature_algorithm_oid: String,
    pub signature_algorithm_parameters_present: bool,
    pub extension_oids: Vec<String>,
    pub subject_key_identifier: Option<Vec<u8>>,
    pub authority_key_identifier: Option<Vec<u8>>,
}

impl ParsedCertificate {
    /// Parse a DER certificate.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let malformed = |reason: String| KeystoneError::InvalidCertificate(reason);

        let (rest, certificate) = X509Certificate::from_der(der)
            .map_err(|e| malformed(format!("cannot parse DER: {e}")))?;
        if !rest.is_empty() {
            return Err(malformed(format!(
                "{} trailing bytes after the certificate",
                rest.len()
            )));
        }

        let public_key_sec1 = p256_public_key(&certificate)?;

        if certificate.signature_algorithm != certificate.tbs_certificate.signature {
            return Err(malformed(
                "certificate's outer and TBS signature algorithms differ".to_string(),
            ));
        }

        let mut seen_extension_oids = HashSet::new();
        let mut extension_oids = Vec::with_capacity(certificate.extensions().len());
        for extension in certificate.extensions() {
            let oid = extension.oid.to_id_string();
            if !seen_extension_oids.insert(oid.clone()) {
                return Err(malformed(format!(
                    "certificate contains duplicate extension {oid}"
                )));
            }
            extension_oids.push(oid);
        }

        let (is_ca, basic_constraints_critical, path_len) = match certificate
            .basic_constraints()
            .map_err(|e| malformed(format!("cannot read basic constraints: {e}")))?
        {
            Some(extension) => (
                extension.value.ca,
                extension.critical,
                extension.value.path_len_constraint,
            ),
            // An absent basicConstraints means an end-entity certificate.
            None => (false, false, None),
        };

        let key_usage = certificate
            .key_usage()
            .map_err(|e| malformed(format!("cannot read key usage: {e}")))?;

        let mut uri_sans = Vec::new();
        let mut dns_sans = Vec::new();
        let mut other_san_count = 0;
        if let Some(extension) = certificate
            .subject_alternative_name()
            .map_err(|e| malformed(format!("cannot read subject alternative names: {e}")))?
        {
            for name in &extension.value.general_names {
                match name {
                    GeneralName::URI(uri) => uri_sans.push((*uri).to_string()),
                    GeneralName::DNSName(dns) => dns_sans.push((*dns).to_string()),
                    _ => other_san_count += 1,
                }
            }
        }

        let mut subject_key_identifier = None;
        let mut authority_key_identifier = None;
        for extension in certificate.extensions() {
            match extension.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(identifier) => {
                    subject_key_identifier = Some(identifier.0.to_vec());
                }
                ParsedExtension::AuthorityKeyIdentifier(identifier) => {
                    authority_key_identifier = identifier
                        .key_identifier
                        .as_ref()
                        .map(|identifier| identifier.0.to_vec());
                }
                _ => {}
            }
        }

        Ok(Self {
            der: der.to_vec(),
            // `x509_parser` reports the raw version integer: 2 means v3.
            version: certificate.version().0 + 1,
            // Decimal, because that is the form AWS expects in the credential
            // field of the authorization header.
            serial_decimal: certificate.tbs_certificate.serial.to_str_radix(10),
            subject: certificate.subject().to_string(),
            issuer: certificate.issuer().to_string(),
            not_before: certificate.validity().not_before.to_datetime(),
            not_after: certificate.validity().not_after.to_datetime(),
            is_ca,
            basic_constraints_critical,
            path_len,
            key_usage_digital_signature: key_usage
                .as_ref()
                .is_some_and(|k| k.value.digital_signature()),
            key_usage_key_cert_sign: key_usage.as_ref().is_some_and(|k| k.value.key_cert_sign()),
            key_usage_crl_sign: key_usage.as_ref().is_some_and(|k| k.value.crl_sign()),
            key_usage_critical: key_usage.as_ref().is_some_and(|k| k.critical),
            key_usage_flags: key_usage.as_ref().map_or(0, |k| k.value.flags),
            public_key_sec1,
            uri_sans,
            dns_sans,
            other_san_count,
            signature_algorithm_oid: certificate.signature_algorithm.algorithm.to_id_string(),
            signature_algorithm_parameters_present: certificate
                .signature_algorithm
                .parameters
                .is_some(),
            extension_oids,
            subject_key_identifier,
            authority_key_identifier,
        })
    }

    /// Parse a PEM certificate, requiring exactly one.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let mut certificates = Self::from_pem_bundle(pem)?;
        if certificates.len() != 1 {
            return Err(KeystoneError::InvalidCertificate(format!(
                "expected exactly one certificate, found {}",
                certificates.len()
            )));
        }
        Ok(certificates.remove(0))
    }

    /// Parse every certificate in a PEM bundle, in file order.
    pub fn from_pem_bundle(pem: &str) -> Result<Vec<Self>> {
        let mut certificates = Vec::new();
        for entry in Pem::iter_from_buffer(pem.as_bytes()) {
            let entry = entry
                .map_err(|e| KeystoneError::InvalidCertificate(format!("cannot parse PEM: {e}")))?;
            if entry.label != PEM_LABEL {
                return Err(KeystoneError::InvalidCertificate(format!(
                    "PEM block is {:?}, expected {PEM_LABEL:?}",
                    entry.label
                )));
            }
            certificates.push(Self::from_der(&entry.contents)?);
        }
        if certificates.is_empty() {
            return Err(KeystoneError::InvalidCertificate(
                "no PEM certificate found".to_string(),
            ));
        }
        Ok(certificates)
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The PEM encoding, which is what Keystone writes to disk.
    pub fn to_pem(&self) -> String {
        encode_pem(PEM_LABEL, &self.der)
    }

    /// SHA-256 over the DER, the standard certificate fingerprint.
    pub fn fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of(&self.der)
    }

    pub fn public_key_fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of(&self.public_key_sec1)
    }

    /// The Keystone device key ID, from the URI SAN.
    pub fn device_key_id(&self) -> Option<KeyId> {
        self.uri_sans
            .iter()
            .find_map(|uri| KeyId::from_device_san_uri(uri))
    }

    /// Whether the certificate is within its validity window at `now`.
    pub fn is_valid_at(&self, now: OffsetDateTime) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    /// Time remaining before expiry, negative once expired.
    pub fn remaining(&self, now: OffsetDateTime) -> time::Duration {
        self.not_after - now
    }
}

/// Extract a P-256 public key, refusing anything Keystone cannot use.
fn p256_public_key(certificate: &X509Certificate<'_>) -> Result<[u8; 65]> {
    let public_key = certificate.public_key();
    let algorithm = &public_key.algorithm;

    // id-ecPublicKey
    const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
    // prime256v1 / secp256r1
    const P256_OID: &str = "1.2.840.10045.3.1.7";

    if algorithm.algorithm.to_id_string() != EC_PUBLIC_KEY_OID {
        return Err(KeystoneError::InvalidCertificate(format!(
            "public key algorithm {} is not EC; Keystone requires P-256",
            algorithm.algorithm
        )));
    }
    let curve = algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
        .map(|oid| oid.to_id_string())
        .ok_or_else(|| {
            KeystoneError::InvalidCertificate(
                "EC public key does not name a named curve".to_string(),
            )
        })?;
    if curve != P256_OID {
        return Err(KeystoneError::InvalidCertificate(format!(
            "EC curve {curve} is not P-256"
        )));
    }

    let bytes = public_key.subject_public_key.as_ref();
    let bytes: [u8; 65] = bytes.try_into().map_err(|_| {
        KeystoneError::InvalidCertificate(format!(
            "P-256 public key must be 65 bytes uncompressed, found {}",
            bytes.len()
        ))
    })?;
    if bytes[0] != 0x04 {
        return Err(KeystoneError::InvalidCertificate(
            "P-256 public key is not an uncompressed SEC1 point".to_string(),
        ));
    }
    Ok(bytes)
}

/// PEM-encode DER bytes with 64-character lines, as OpenSSL does.
pub fn encode_pem(label: &str, der: &[u8]) -> String {
    use base64::prelude::{Engine as _, BASE64_STANDARD};

    let encoded = BASE64_STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, TestCa};

    #[test]
    fn a_generated_device_certificate_parses_with_the_expected_fields() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();

        assert_eq!(leaf.version, 3);
        assert!(!leaf.is_ca);
        assert!(leaf.basic_constraints_critical);
        assert!(leaf.key_usage_digital_signature);
        assert!(leaf.key_usage_critical);
        assert!(!leaf.key_usage_key_cert_sign);
        assert_eq!(leaf.public_key_sec1, bundle.device_public_key);
        assert_eq!(leaf.device_key_id().as_ref(), Some(&bundle.key_id));
        assert!(leaf.subject.contains(&bundle.device_name));
        assert!(!leaf.is_self_issued());
    }

    #[test]
    fn a_generated_ca_certificate_reports_its_ca_constraints() {
        let bundle = testing::device_bundle();
        let ca = ParsedCertificate::from_der(bundle.ca_der()).unwrap();

        assert!(ca.is_ca);
        assert!(ca.basic_constraints_critical);
        assert_eq!(ca.path_len, Some(0));
        assert!(ca.key_usage_key_cert_sign);
        assert!(ca.key_usage_crl_sign);
        assert!(!ca.key_usage_digital_signature);
        assert!(ca.is_self_issued());
    }

    #[test]
    fn the_serial_number_is_reported_as_decimal_digits() {
        // AWS puts this value in the credential field of the authorization
        // header, where it must be decimal.
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        assert!(
            leaf.serial_decimal.chars().all(|c| c.is_ascii_digit()),
            "{}",
            leaf.serial_decimal
        );
        assert!(!leaf.serial_decimal.is_empty());
    }

    #[test]
    fn certificates_round_trip_through_pem() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let reparsed = ParsedCertificate::from_pem(&leaf.to_pem()).unwrap();
        assert_eq!(reparsed.der(), leaf.der());
        assert_eq!(reparsed.fingerprint(), leaf.fingerprint());
    }

    #[test]
    fn a_pem_bundle_yields_certificates_in_file_order() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let ca = ParsedCertificate::from_der(bundle.ca_der()).unwrap();
        let text = format!("{}{}", leaf.to_pem(), ca.to_pem());

        let parsed = ParsedCertificate::from_pem_bundle(&text).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].fingerprint(), leaf.fingerprint());
        assert_eq!(parsed[1].fingerprint(), ca.fingerprint());
    }

    #[test]
    fn a_bundle_where_one_certificate_was_expected_is_refused() {
        let bundle = testing::device_bundle();
        let leaf = ParsedCertificate::from_der(bundle.leaf_der()).unwrap();
        let doubled = format!("{}{}", leaf.to_pem(), leaf.to_pem());
        assert!(ParsedCertificate::from_pem(&doubled).is_err());
    }

    #[test]
    fn non_certificate_pem_is_refused() {
        // A private key pasted where a certificate belongs must not be accepted.
        let key_pem = "-----BEGIN PRIVATE KEY-----\nMC4=\n-----END PRIVATE KEY-----\n";
        let error = ParsedCertificate::from_pem(key_pem).unwrap_err();
        assert!(error.to_string().contains("PRIVATE KEY"), "{error}");
    }

    #[test]
    fn empty_and_garbage_input_is_refused() {
        assert!(ParsedCertificate::from_pem("").is_err());
        assert!(ParsedCertificate::from_pem("not a pem file").is_err());
        assert!(ParsedCertificate::from_der(&[]).is_err());
        assert!(ParsedCertificate::from_der(b"\x30\x82\x01\x00garbage").is_err());
    }

    #[test]
    fn trailing_bytes_after_the_der_certificate_are_refused() {
        let bundle = testing::device_bundle();
        let mut der = bundle.leaf_der().to_vec();
        der.push(0);
        let error = ParsedCertificate::from_der(&der).unwrap_err();
        assert!(error.to_string().contains("trailing"), "{error}");
    }

    #[test]
    fn a_non_p256_certificate_is_refused_at_parse_time() {
        // Keystone cannot sign with any other curve, so an Ed25519 or P-384
        // certificate is rejected before any validation rule runs.
        for certificate in [
            testing::certificate_with_other_algorithm(&rcgen::PKCS_ED25519),
            testing::certificate_with_other_algorithm(&rcgen::PKCS_ECDSA_P384_SHA384),
        ] {
            let error = ParsedCertificate::from_der(&certificate).unwrap_err();
            assert!(
                error.to_string().contains("P-256"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn validity_windows_are_reported_against_a_supplied_time() {
        let ca = TestCa::generate();
        let issued = ca.issue_device_certificate(
            &testing::random_device_key(),
            "example-laptop",
            &KeyId::generate(),
            time::macros::datetime!(2026-01-01 0:00 UTC),
            time::macros::datetime!(2027-01-01 0:00 UTC),
        );
        let leaf = ParsedCertificate::from_der(&issued).unwrap();

        assert!(leaf.is_valid_at(time::macros::datetime!(2026-06-01 0:00 UTC)));
        assert!(!leaf.is_valid_at(time::macros::datetime!(2025-06-01 0:00 UTC)));
        assert!(!leaf.is_valid_at(time::macros::datetime!(2028-06-01 0:00 UTC)));
        assert_eq!(
            leaf.remaining(time::macros::datetime!(2026-12-02 0:00 UTC))
                .whole_days(),
            30
        );
        assert!(leaf
            .remaining(time::macros::datetime!(2027-02-01 0:00 UTC))
            .is_negative());
    }

    #[test]
    fn a_certificate_without_a_device_san_reports_no_key_id() {
        let ca = TestCa::generate();
        let der = ca.issue_certificate_with_uri_san(
            &testing::random_device_key(),
            "example-laptop",
            Some("urn:example:other:1"),
        );
        let leaf = ParsedCertificate::from_der(&der).unwrap();
        assert!(leaf.device_key_id().is_none());
        assert_eq!(leaf.uri_sans, vec!["urn:example:other:1".to_string()]);
    }

    #[test]
    fn pem_encoding_wraps_at_64_characters() {
        let pem = encode_pem("CERTIFICATE", &[0x41; 200]);
        let body: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(body.len() > 1);
        for line in &body[..body.len() - 1] {
            assert_eq!(line.len(), 64);
        }
    }
}
