//! Certificate parameter construction.
//!
//! One place builds the device certificate's fields, so the ephemeral CA, CSR
//! enrollment, and the validation rules cannot drift apart: a certificate
//! Keystone issues must be one Keystone would also accept.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyUsagePurpose, SanType,
};
use time::OffsetDateTime;

/// The organizational unit Keystone device certificates carry.
pub const DEVICE_OU: &str = "Keystone Devices";

/// Default device-certificate lifetime, per the design's `--leaf-validity 5y`.
pub const DEFAULT_LEAF_VALIDITY_DAYS: i64 = 5 * 365;

/// Default ephemeral-CA lifetime, per `--ca-validity 10y`.
///
/// The CA must outlive the leaf, or the chain stops validating while the device
/// certificate still looks current.
pub const DEFAULT_CA_VALIDITY_DAYS: i64 = 10 * 365;

/// What goes into a device certificate.
#[derive(Debug, Clone)]
pub struct DeviceCertificateSpec {
    /// Becomes the subject `CN`. Display only — authorization uses the URI SAN.
    pub device_name: String,
    /// Optional subject `O`.
    pub organization: Option<String>,
    pub key_id: KeyId,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl DeviceCertificateSpec {
    /// A spec with the default lifetime starting now.
    pub fn new(device_name: impl Into<String>, key_id: KeyId, now: OffsetDateTime) -> Self {
        Self {
            device_name: device_name.into(),
            organization: None,
            key_id,
            not_before: now,
            not_after: now + time::Duration::days(DEFAULT_LEAF_VALIDITY_DAYS),
        }
    }

    pub fn with_organization(mut self, organization: Option<String>) -> Self {
        self.organization = organization;
        self
    }

    pub fn with_validity(mut self, not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    /// The URI SAN that IAM policies condition on.
    pub fn device_san_uri(&self) -> String {
        self.key_id.device_san_uri()
    }

    /// Build the rcgen parameters for the device certificate.
    pub fn to_params(&self) -> Result<CertificateParams> {
        validate_name("device name", &self.device_name)?;
        if let Some(organization) = &self.organization {
            validate_name("organization", organization)?;
        }
        if self.not_after <= self.not_before {
            return Err(KeystoneError::InvalidConfiguration(
                "certificate validity must end after it begins".to_string(),
            ));
        }

        let mut params = CertificateParams::default();
        params.distinguished_name = self.distinguished_name();
        params.not_before = self.not_before;
        params.not_after = self.not_after;
        // `ExplicitNoCa` emits basicConstraints with CA=false rather than
        // omitting the extension, which is what IAM Roles Anywhere expects of an
        // end-entity certificate.
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.subject_alt_names = vec![SanType::URI(self.device_san_uri().try_into().map_err(
            |e| KeystoneError::Other(format!("device SAN is not a valid IA5 string: {e}")),
        )?)];
        params.use_authority_key_identifier_extension = true;
        Ok(params)
    }

    /// The same parameters, minus the fields a PKCS#10 request cannot carry.
    ///
    /// A CSR describes what the subject is asking for, so the authority key
    /// identifier — which only the issuing CA can know — is dropped; rcgen
    /// refuses to build a request that specifies it.
    pub fn to_csr_params(&self) -> Result<CertificateParams> {
        let mut params = self.to_params()?;
        params.use_authority_key_identifier_extension = false;
        Ok(params)
    }

    fn distinguished_name(&self) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, self.device_name.clone());
        name.push(DnType::OrganizationalUnitName, DEVICE_OU);
        if let Some(organization) = &self.organization {
            name.push(DnType::OrganizationName, organization.clone());
        }
        name
    }
}

/// What goes into the one-shot CA certificate.
#[derive(Debug, Clone)]
pub struct EphemeralCaSpec {
    pub key_id: KeyId,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl EphemeralCaSpec {
    pub fn new(key_id: KeyId, now: OffsetDateTime) -> Self {
        Self {
            key_id,
            not_before: now,
            not_after: now + time::Duration::days(DEFAULT_CA_VALIDITY_DAYS),
        }
    }

    pub fn with_validity(mut self, not_before: OffsetDateTime, not_after: OffsetDateTime) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    pub fn common_name(&self) -> String {
        format!("Keystone Ephemeral CA {}", self.key_id)
    }

    pub fn to_params(&self) -> Result<CertificateParams> {
        if self.not_after <= self.not_before {
            return Err(KeystoneError::InvalidConfiguration(
                "CA validity must end after it begins".to_string(),
            ));
        }

        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, self.common_name());

        let mut params = CertificateParams::default();
        params.distinguished_name = name;
        params.not_before = self.not_before;
        params.not_after = self.not_after;
        // pathLen=0: this CA may issue end-entity certificates only, never
        // another CA.
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        Ok(params)
    }
}

/// Reject a name that cannot go into a certificate subject.
///
/// The value is user-supplied and ends up in a DER string and in generated CDK
/// source, so control characters and absurd lengths are refused early with a
/// clear message rather than failing deep inside the encoder.
fn validate_name(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{field} must not be empty"
        )));
    }
    if value.chars().count() > 64 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{field} must be at most 64 characters"
        )));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{field} must not contain control characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn spec() -> DeviceCertificateSpec {
        DeviceCertificateSpec::new("example-laptop", KeyId::parse("019cabc").unwrap(), NOW)
    }

    #[test]
    fn a_device_spec_defaults_to_a_five_year_lifetime() {
        let spec = spec();
        assert_eq!(
            (spec.not_after - spec.not_before).whole_days(),
            DEFAULT_LEAF_VALIDITY_DAYS
        );
    }

    #[test]
    fn a_ca_outlives_the_device_certificate_by_default() {
        // Otherwise the chain stops validating while the leaf still looks current.
        let device = spec();
        let ca = EphemeralCaSpec::new(KeyId::parse("019cabc").unwrap(), NOW);
        assert!(ca.not_after > device.not_after);
    }

    #[test]
    fn the_device_certificate_is_marked_as_an_end_entity() {
        let params = spec().to_params().unwrap();
        assert_eq!(params.is_ca, IsCa::ExplicitNoCa);
        assert_eq!(params.key_usages, vec![KeyUsagePurpose::DigitalSignature]);
    }

    #[test]
    fn the_device_certificate_carries_the_key_id_as_a_uri_san() {
        let params = spec().to_params().unwrap();
        assert_eq!(params.subject_alt_names.len(), 1);
        match &params.subject_alt_names[0] {
            SanType::URI(uri) => assert_eq!(uri.to_string(), "urn:keystone:device:019cabc"),
            other => panic!("unexpected SAN: {other:?}"),
        }
    }

    #[test]
    fn the_device_subject_names_the_keystone_ou() {
        let spec = spec().with_organization(Some("Example Org".to_string()));
        let params = spec.to_params().unwrap();
        let rendered = format!("{:?}", params.distinguished_name);
        assert!(rendered.contains("example-laptop"), "{rendered}");
        assert!(rendered.contains(DEVICE_OU), "{rendered}");
        assert!(rendered.contains("Example Org"), "{rendered}");
    }

    #[test]
    fn the_ca_is_constrained_to_issuing_end_entity_certificates() {
        let ca = EphemeralCaSpec::new(KeyId::parse("019cabc").unwrap(), NOW);
        let params = ca.to_params().unwrap();
        assert_eq!(params.is_ca, IsCa::Ca(BasicConstraints::Constrained(0)));
        assert_eq!(
            params.key_usages,
            vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
        );
        // The CA cannot sign requests, only certificates.
        assert!(!params
            .key_usages
            .contains(&KeyUsagePurpose::DigitalSignature));
    }

    #[test]
    fn the_ca_common_name_identifies_the_device_it_was_created_for() {
        let ca = EphemeralCaSpec::new(KeyId::parse("019cabc").unwrap(), NOW);
        assert_eq!(ca.common_name(), "Keystone Ephemeral CA 019cabc");
    }

    #[test]
    fn an_inverted_validity_window_is_refused() {
        let spec = spec().with_validity(NOW, NOW - time::Duration::days(1));
        assert!(spec.to_params().is_err());

        let ca =
            EphemeralCaSpec::new(KeyId::parse("019cabc").unwrap(), NOW).with_validity(NOW, NOW);
        assert!(ca.to_params().is_err());
    }

    #[test]
    fn implausible_device_names_are_refused() {
        for name in ["", "   ", "with\nnewline", "with\0null"] {
            let mut spec = spec();
            spec.device_name = name.to_string();
            assert!(spec.to_params().is_err(), "should reject {name:?}");
        }
        let mut spec = spec();
        spec.device_name = "x".repeat(65);
        assert!(spec.to_params().is_err());
    }

    #[test]
    fn an_implausible_organization_is_refused() {
        let spec = spec().with_organization(Some("bad\nname".to_string()));
        assert!(spec.to_params().is_err());
    }
}
