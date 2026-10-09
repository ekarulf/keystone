//! Building and signing the `CreateSession` request.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::redact;
use serde::Serialize;
use time::OffsetDateTime;

use crate::signing::{
    authorization_header, canonical_request, credential_scope, format_amz_date, string_to_sign,
    SignedHeaders, ALGORITHM_ECDSA_SHA256, CREATE_SESSION_PATH,
};

/// The X.509 identity used to authenticate to IAM Roles Anywhere.
///
/// Separate from `KeystoneSigningIdentity` because signing an AWS request needs
/// the certificate as well as the key: the serial number goes in the credential
/// field and the certificate itself goes in a header. The signing method takes
/// the string-to-sign as a message and hashes it internally with SHA-256,
/// matching both CryptoKit's `signature(for:)` and the official helper.
pub trait AwsX509Identity {
    /// The certificate serial number, in decimal, as AWS expects in the
    /// credential field.
    fn certificate_serial_decimal(&self) -> Result<String>;

    /// The DER-encoded leaf certificate.
    fn leaf_certificate_der(&self) -> &[u8];

    /// The DER-encoded intermediates, leaf-to-root, excluding the leaf and the
    /// trust anchor itself.
    fn certificate_chain_der(&self) -> &[Vec<u8>];

    /// Sign the string-to-sign, returning a DER ECDSA signature.
    fn sign_string_to_sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>>;
}

/// A borrowed identity is an identity.
///
/// [`crate::client::RolesAnywhereClient`] takes its identity by value, so this is
/// what lets a caller hand it a borrow of an identity it owns and still use that
/// identity afterwards — the alternative is cloning a certificate and a key
/// handle per exchange.
impl<T: AwsX509Identity + ?Sized> AwsX509Identity for &T {
    fn certificate_serial_decimal(&self) -> Result<String> {
        (**self).certificate_serial_decimal()
    }

    fn leaf_certificate_der(&self) -> &[u8] {
        (**self).leaf_certificate_der()
    }

    fn certificate_chain_der(&self) -> &[Vec<u8>] {
        (**self).certificate_chain_der()
    }

    fn sign_string_to_sign(&self, string_to_sign: &[u8]) -> Result<Vec<u8>> {
        (**self).sign_string_to_sign(string_to_sign)
    }
}

/// The `CreateSession` request parameters.
#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub profile_arn: String,
    pub role_arn: String,
    pub trust_anchor_arn: String,
    pub duration_seconds: u32,
    pub role_session_name: Option<String>,
}

/// The JSON body, in the field order the AWS API documents.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionBody<'a> {
    duration_seconds: u32,
    profile_arn: &'a str,
    role_arn: &'a str,
    /// `roleSessionName`, not `sessionName`.
    ///
    /// `CreateSession` accepts both. `sessionName` is marked deprecated in the
    /// AWS API model and is *ignored*: sending it succeeds, and Roles Anywhere
    /// then derives a session name itself from the certificate's public key, so
    /// CloudTrail shows `assumed-role/<role>/1fb91081daf1...`. There is no error
    /// to notice — only an opaque name where a device name belongs. The official
    /// helper sets `SessionName: nil` and populates `RoleSessionName`.
    #[serde(skip_serializing_if = "Option::is_none")]
    role_session_name: Option<&'a str>,
    trust_anchor_arn: &'a str,
}

impl CreateSessionRequest {
    /// Serialize the request body.
    ///
    /// Called once per signing attempt; the resulting bytes are both hashed for
    /// the canonical request and sent as the body. Re-serializing could produce
    /// different bytes and therefore a signature that does not match the body.
    pub fn serialize_body(&self) -> Result<Vec<u8>> {
        let body = CreateSessionBody {
            duration_seconds: self.duration_seconds,
            profile_arn: &self.profile_arn,
            role_arn: &self.role_arn,
            role_session_name: self.role_session_name.as_deref(),
            trust_anchor_arn: &self.trust_anchor_arn,
        };
        serde_json::to_vec(&body)
            .map_err(|e| KeystoneError::Other(format!("cannot serialize CreateSession body: {e}")))
    }
}

/// A fully signed request, ready to send.
///
/// Holds the exact body bytes that were hashed, so the transport cannot
/// accidentally send a re-serialized version.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Kept for golden tests and `--debug-signing`.
    pub canonical_request: String,
    pub string_to_sign: String,
}

impl SignedRequest {
    /// Render the request for diagnostics with secrets removed.
    pub fn to_redacted_string(&self) -> String {
        let mut out = format!("POST {}\n", self.url);
        for (name, value) in &self.headers {
            let line = if name.eq_ignore_ascii_case("authorization") {
                format!("{name}: {}", redact::redact_authorization(value))
            } else if name.eq_ignore_ascii_case("x-amz-x509")
                || name.eq_ignore_ascii_case("x-amz-x509-chain")
            {
                // The certificate is public, but printing it in full buries the
                // fields that matter when comparing requests.
                format!("{name}: {}", redact::truncate_opaque(value))
            } else {
                format!("{name}: {value}")
            };
            out.push_str(&line);
            out.push('\n');
        }
        out.push_str(&format!("\n{}\n", String::from_utf8_lossy(&self.body)));
        out
    }
}

/// The regional `CreateSession` endpoint.
///
/// Only the standard `aws` partition is supported in v0; other partitions use
/// different suffixes, and guessing one would produce a confusing TLS or DNS
/// error rather than a clear message.
pub fn endpoint_for_region(region: &str) -> Result<String> {
    keystone_core::config::validate_region(region)?;
    if region.starts_with("cn-") {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "region {region:?} is in the aws-cn partition, which Keystone does not support yet"
        )));
    }
    if region.starts_with("us-iso") || region.starts_with("us-gov") {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "region {region:?} is in a partition Keystone does not support yet"
        )));
    }
    Ok(format!("https://rolesanywhere.{region}.amazonaws.com"))
}

/// Signs `CreateSession` requests with an X.509 identity.
pub struct RolesAnywhereRequestSigner<I> {
    identity: I,
    region: String,
}

impl<I: AwsX509Identity> RolesAnywhereRequestSigner<I> {
    pub fn new(identity: I, region: impl Into<String>) -> Self {
        Self {
            identity,
            region: region.into(),
        }
    }

    pub fn identity(&self) -> &I {
        &self.identity
    }

    /// Build and sign a request at the given timestamp.
    ///
    /// The timestamp is a parameter rather than read from a clock here, so that
    /// each retry signs with a fresh time and golden tests can pin one.
    pub fn sign(
        &self,
        request: &CreateSessionRequest,
        timestamp: OffsetDateTime,
    ) -> Result<SignedRequest> {
        keystone_core::time::check_plausible(timestamp)?;

        let endpoint = endpoint_for_region(&self.region)?;
        let host = endpoint
            .strip_prefix("https://")
            .ok_or_else(|| KeystoneError::Other("endpoint is not https".to_string()))?
            .to_string();

        let body = request.serialize_body()?;
        let amz_date = format_amz_date(timestamp)?;

        let mut headers = SignedHeaders::new();
        headers
            .insert("content-type", "application/json")
            .insert("host", &host)
            .insert("x-amz-date", &amz_date)
            .insert(
                "x-amz-x509",
                BASE64_STANDARD.encode(self.identity.leaf_certificate_der()),
            );

        // The chain header is set only when intermediates exist; an empty header
        // is not the same as an absent one to AWS.
        let chain = self.identity.certificate_chain_der();
        if !chain.is_empty() {
            let encoded = chain
                .iter()
                .map(|der| BASE64_STANDARD.encode(der))
                .collect::<Vec<_>>()
                .join(",");
            headers.insert("x-amz-x509-chain", encoded);
        }

        let canonical = canonical_request(&headers, &body);
        let sts = string_to_sign(ALGORITHM_ECDSA_SHA256, timestamp, &self.region, &canonical)?;

        let signature_der = self.identity.sign_string_to_sign(sts.as_bytes())?;
        let authorization = authorization_header(
            ALGORITHM_ECDSA_SHA256,
            &self.identity.certificate_serial_decimal()?,
            &credential_scope(timestamp, &self.region)?,
            &canonical.signed_header_list,
            &hex::encode(&signature_der),
        );

        let mut final_headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        final_headers.push(("authorization".to_string(), authorization));

        Ok(SignedRequest {
            url: format!("{endpoint}{CREATE_SESSION_PATH}"),
            headers: final_headers,
            body,
            canonical_request: canonical.canonical_request,
            string_to_sign: sts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestIdentity;

    const TIMESTAMP: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn request() -> CreateSessionRequest {
        CreateSessionRequest {
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/p".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/ExampleDeviceRole".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/t"
                .to_string(),
            duration_seconds: 3600,
            role_session_name: Some("example-laptop".to_string()),
        }
    }

    #[test]
    fn endpoints_follow_the_regional_pattern() {
        assert_eq!(
            endpoint_for_region("us-east-1").unwrap(),
            "https://rolesanywhere.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn unsupported_partitions_are_refused_with_a_clear_message() {
        for region in ["cn-north-1", "us-gov-west-1", "us-iso-east-1"] {
            let error = endpoint_for_region(region).unwrap_err().to_string();
            assert!(error.contains("does not support"), "{error}");
        }
    }

    #[test]
    fn an_implausible_region_cannot_reach_the_endpoint_string() {
        assert!(endpoint_for_region("us-east-1/../evil").is_err());
        assert!(endpoint_for_region("").is_err());
    }

    #[test]
    fn the_body_contains_the_documented_fields() {
        let body = request().serialize_body().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["durationSeconds"], 3600);
        assert_eq!(
            parsed["roleArn"],
            "arn:aws:iam::123456789012:role/ExampleDeviceRole"
        );
        assert_eq!(parsed["roleSessionName"], "example-laptop");
        assert!(parsed["profileArn"].is_string());
        assert!(parsed["trustAnchorArn"].is_string());
    }

    #[test]
    fn the_session_name_uses_the_field_aws_honors_rather_than_the_deprecated_one() {
        // `CreateSession` accepts `sessionName` too, and silently ignores it:
        // credentials come back fine, but named after a hash of the public key
        // instead of the device. Nothing fails, so only this assertion catches it.
        let body = request().serialize_body().unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(
            text.contains(r#""roleSessionName":"example-laptop""#),
            "{text}"
        );
        assert!(
            !text.contains(r#""sessionName""#),
            "the deprecated field must not be sent: {text}"
        );
    }

    #[test]
    fn an_absent_session_name_is_omitted_rather_than_sent_as_null() {
        let mut request = request();
        request.role_session_name = None;
        let body = request.serialize_body().unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(!text.contains("essionName"), "{text}");
    }

    #[test]
    fn body_serialization_is_stable_across_calls() {
        // The signature commits to these exact bytes.
        let request = request();
        assert_eq!(
            request.serialize_body().unwrap(),
            request.serialize_body().unwrap()
        );
    }

    #[test]
    fn a_signed_request_carries_every_required_header() {
        let identity = TestIdentity::new();
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let signed = signer.sign(&request(), TIMESTAMP).unwrap();

        let names: Vec<&str> = signed.headers.iter().map(|(n, _)| n.as_str()).collect();
        for expected in [
            "content-type",
            "host",
            "x-amz-date",
            "x-amz-x509",
            "authorization",
        ] {
            assert!(names.contains(&expected), "missing {expected} in {names:?}");
        }
        assert_eq!(
            signed.url,
            "https://rolesanywhere.us-east-1.amazonaws.com/sessions"
        );
    }

    #[test]
    fn the_signature_verifies_against_the_certificate_public_key() {
        let identity = TestIdentity::new();
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let signed = signer.sign(&request(), TIMESTAMP).unwrap();

        let signature_hex = signed
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .map(|(_, value)| {
                value
                    .split("Signature=")
                    .nth(1)
                    .expect("authorization has a signature")
                    .to_string()
            })
            .expect("authorization header present");

        let signature = hex::decode(signature_hex).unwrap();
        // ECDSA is nondeterministic, so the test verifies the signature rather
        // than comparing bytes to a fixture.
        assert!(identity.verify(signed.string_to_sign.as_bytes(), &signature));
    }

    #[test]
    fn the_signed_body_is_the_body_that_was_hashed() {
        let identity = TestIdentity::new();
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let signed = signer.sign(&request(), TIMESTAMP).unwrap();
        let body_hash = crate::signing::hex_sha256(&signed.body);
        assert!(
            signed.canonical_request.ends_with(&body_hash),
            "canonical request does not commit to the body actually sent"
        );
    }

    #[test]
    fn the_chain_header_is_absent_when_there_are_no_intermediates() {
        let identity = TestIdentity::new();
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let signed = signer.sign(&request(), TIMESTAMP).unwrap();
        assert!(!signed
            .headers
            .iter()
            .any(|(name, _)| name == "x-amz-x509-chain"));
    }

    #[test]
    fn intermediates_are_comma_separated_in_the_chain_header() {
        let identity = TestIdentity::new().with_chain(vec![
            b"intermediate-one".to_vec(),
            b"intermediate-two".to_vec(),
        ]);
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let signed = signer.sign(&request(), TIMESTAMP).unwrap();

        let chain = signed
            .headers
            .iter()
            .find(|(name, _)| name == "x-amz-x509-chain")
            .map(|(_, value)| value.clone())
            .expect("chain header present");
        let parts: Vec<&str> = chain.split(',').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(
            BASE64_STANDARD.decode(parts[0]).unwrap(),
            b"intermediate-one"
        );
        // Adding a chain changes the signed headers, and so the signature.
        assert!(signed.canonical_request.contains("x-amz-x509-chain"));
    }

    #[test]
    fn signing_refuses_an_implausible_clock() {
        let identity = TestIdentity::new();
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let stale = time::macros::datetime!(2001-01-01 0:00 UTC);
        assert!(matches!(
            signer.sign(&request(), stale),
            Err(KeystoneError::ClockSkew)
        ));
    }

    #[test]
    fn redacted_output_hides_the_signature_but_keeps_the_scope() {
        let identity = TestIdentity::new();
        let signer = RolesAnywhereRequestSigner::new(&identity, "us-east-1");
        let signed = signer.sign(&request(), TIMESTAMP).unwrap();

        let rendered = signed.to_redacted_string();
        assert!(rendered.contains("Credential="), "{rendered}");
        assert!(rendered.contains("SignedHeaders="), "{rendered}");
        assert!(rendered.contains(redact::REDACTED), "{rendered}");

        let signature = signed
            .headers
            .iter()
            .find(|(name, _)| name == "authorization")
            .and_then(|(_, v)| v.split("Signature=").nth(1))
            .unwrap();
        assert!(!rendered.contains(signature), "signature leaked");
    }
}
