//! AWS4-X509 request signing for IAM Roles Anywhere.
//!
//! The canonicalization here is ported from the official
//! `rolesanywhere-credential-helper` (`aws_signing_helper/signer.go`) rather
//! than re-derived from the SigV4 specification, because Roles Anywhere differs
//! from ordinary SigV4 in ways that are easy to get subtly wrong:
//!
//! * the credential field carries the certificate serial number in decimal,
//!   where SigV4 carries an access-key ID;
//! * there is no derived signing key and no HMAC chain — the string-to-sign is
//!   signed directly by the certificate's private key;
//! * the DER ECDSA signature is hex-encoded as-is, not converted to `r || s`;
//! * `authorization`, `user-agent`, and `x-amzn-trace-id` are excluded from the
//!   signed headers.
//!
//! Keystone's novelty is the Secure Enclave signer, not this encoding.

use std::collections::BTreeMap;

use keystone_core::error::{KeystoneError, Result};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// The signing algorithm for a P-256 certificate.
pub const ALGORITHM_ECDSA_SHA256: &str = "AWS4-X509-ECDSA-SHA256";

/// The service name used in the credential scope.
pub const SIGNING_NAME: &str = "rolesanywhere";

/// The `CreateSession` path, which is also the canonical URI.
pub const CREATE_SESSION_PATH: &str = "/sessions";

/// Header names excluded from signing, matching `ignoredHeaderKeys` in the helper.
const IGNORED_HEADERS: &[&str] = &["authorization", "user-agent", "x-amzn-trace-id"];

/// `x-amz-date` format: `20060102T150405Z`.
const AMZ_DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");

/// Credential-scope date format: `20060102`.
const SCOPE_DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year][month][day]");

/// Format a timestamp for the `x-amz-date` header.
pub fn format_amz_date(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .to_offset(time::UtcOffset::UTC)
        .format(AMZ_DATE_FORMAT)
        .map_err(|e| KeystoneError::Other(format!("cannot format signing date: {e}")))
}

/// Format the date component of the credential scope.
pub fn format_scope_date(timestamp: OffsetDateTime) -> Result<String> {
    timestamp
        .to_offset(time::UtcOffset::UTC)
        .format(SCOPE_DATE_FORMAT)
        .map_err(|e| KeystoneError::Other(format!("cannot format signing date: {e}")))
}

/// Build the credential scope: `YYYYMMDD/<region>/rolesanywhere/aws4_request`.
pub fn credential_scope(timestamp: OffsetDateTime, region: &str) -> Result<String> {
    Ok(format!(
        "{}/{region}/{SIGNING_NAME}/aws4_request",
        format_scope_date(timestamp)?
    ))
}

/// The headers of a request being signed.
///
/// A `BTreeMap` keyed by lowercase name gives the sorted order the canonical
/// header string requires, and makes duplicate names impossible to introduce by
/// accident.
#[derive(Debug, Clone, Default)]
pub struct SignedHeaders(BTreeMap<String, String>);

impl SignedHeaders {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Add or replace a header. Ignored headers are dropped, since including
    /// them would produce a signature AWS does not expect.
    pub fn insert(&mut self, name: &str, value: impl Into<String>) -> &mut Self {
        let name = name.to_ascii_lowercase();
        if !IGNORED_HEADERS.contains(&name.as_str()) {
            self.0.insert(name, value.into());
        }
        self
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The `;`-separated list of signed header names.
    pub fn signed_header_list(&self) -> String {
        self.0.keys().cloned().collect::<Vec<_>>().join(";")
    }

    /// The canonical header block: `name:value` lines, sorted, with values
    /// stripped of excess whitespace.
    pub fn canonical_header_string(&self) -> String {
        self.0
            .iter()
            .map(|(name, value)| format!("{name}:{}", strip_excess_spaces(value)))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Collapse runs of spaces and trim the ends, as SigV4 requires.
fn strip_excess_spaces(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_space = false;
    for ch in value.trim_matches(' ').chars() {
        if ch == ' ' {
            if !in_space {
                out.push(ch);
            }
            in_space = true;
        } else {
            out.push(ch);
            in_space = false;
        }
    }
    out
}

/// Hex-encoded SHA-256, lowercase, as used throughout SigV4.
pub fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The canonical request, and the signed-header list it commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRequest {
    pub canonical_request: String,
    pub signed_header_list: String,
}

impl CanonicalRequest {
    /// The hex SHA-256 of the canonical request, which is what the
    /// string-to-sign actually contains.
    pub fn hash(&self) -> String {
        hex_sha256(self.canonical_request.as_bytes())
    }
}

/// Build the canonical request for a `CreateSession` call.
///
/// The method and URI are fixed because `CreateSession` is the only operation
/// Keystone signs, and the query string is always empty. Note the blank line
/// after the header block: SigV4 terminates the canonical headers with a
/// newline, and the format then adds the separator before the signed-header
/// list.
pub fn canonical_request(headers: &SignedHeaders, body: &[u8]) -> CanonicalRequest {
    let signed_header_list = headers.signed_header_list();
    let canonical_request = format!(
        "POST\n{CREATE_SESSION_PATH}\n\n{}\n\n{signed_header_list}\n{}",
        headers.canonical_header_string(),
        hex_sha256(body),
    );
    CanonicalRequest {
        canonical_request,
        signed_header_list,
    }
}

/// Build the string that the certificate's private key signs.
pub fn string_to_sign(
    algorithm: &str,
    timestamp: OffsetDateTime,
    region: &str,
    canonical: &CanonicalRequest,
) -> Result<String> {
    Ok(format!(
        "{algorithm}\n{}\n{}\n{}",
        format_amz_date(timestamp)?,
        credential_scope(timestamp, region)?,
        canonical.hash(),
    ))
}

/// Build the `Authorization` header value.
///
/// `certificate_serial_decimal` occupies the position an access-key ID would in
/// ordinary SigV4, and `signature_hex` is the DER signature hex-encoded
/// directly.
pub fn authorization_header(
    algorithm: &str,
    certificate_serial_decimal: &str,
    scope: &str,
    signed_header_list: &str,
    signature_hex: &str,
) -> String {
    format!(
        "{algorithm} Credential={certificate_serial_decimal}/{scope}, \
         SignedHeaders={signed_header_list}, Signature={signature_hex}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMESTAMP: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    #[test]
    fn dates_use_the_sigv4_formats() {
        assert_eq!(format_amz_date(TIMESTAMP).unwrap(), "20260726T011500Z");
        assert_eq!(format_scope_date(TIMESTAMP).unwrap(), "20260726");
    }

    #[test]
    fn dates_are_normalized_to_utc_before_formatting() {
        // A non-UTC input must not shift the signed date.
        let local = time::macros::datetime!(2026-07-26 03:15:00 +2);
        assert_eq!(format_amz_date(local).unwrap(), "20260726T011500Z");
    }

    #[test]
    fn the_credential_scope_names_the_rolesanywhere_service() {
        assert_eq!(
            credential_scope(TIMESTAMP, "us-east-1").unwrap(),
            "20260726/us-east-1/rolesanywhere/aws4_request"
        );
    }

    #[test]
    fn headers_are_canonicalized_lowercase_and_sorted() {
        let mut headers = SignedHeaders::new();
        headers
            .insert("X-Amz-Date", "20260726T011500Z")
            .insert("Host", "rolesanywhere.us-east-1.amazonaws.com")
            .insert("Content-Type", "application/json");

        assert_eq!(headers.signed_header_list(), "content-type;host;x-amz-date");
        assert_eq!(
            headers.canonical_header_string(),
            "content-type:application/json\n\
             host:rolesanywhere.us-east-1.amazonaws.com\n\
             x-amz-date:20260726T011500Z"
        );
    }

    #[test]
    fn ignored_headers_are_never_signed() {
        // Signing these would produce a signature AWS does not expect.
        let mut headers = SignedHeaders::new();
        headers
            .insert("Host", "example.com")
            .insert("Authorization", "should not be signed")
            .insert("User-Agent", "keystone/0.1.0")
            .insert("X-Amzn-Trace-Id", "Root=1-2-3");
        assert_eq!(headers.signed_header_list(), "host");
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn header_values_have_excess_whitespace_stripped() {
        let mut headers = SignedHeaders::new();
        headers.insert("x-test", "  spaced    out   value  ");
        assert_eq!(headers.canonical_header_string(), "x-test:spaced out value");
    }

    #[test]
    fn repeating_a_header_replaces_rather_than_duplicates_it() {
        let mut headers = SignedHeaders::new();
        headers.insert("host", "first").insert("Host", "second");
        assert_eq!(headers.signed_header_list(), "host");
        assert_eq!(headers.get("host"), Some("second"));
    }

    fn sample_headers() -> SignedHeaders {
        let mut headers = SignedHeaders::new();
        headers
            .insert("content-type", "application/json")
            .insert("host", "rolesanywhere.us-east-1.amazonaws.com")
            .insert("x-amz-date", "20260726T011500Z")
            .insert("x-amz-x509", "TUlJQg==");
        headers
    }

    #[test]
    fn the_canonical_request_has_the_documented_shape() {
        let body = br#"{"durationSeconds":3600}"#;
        let canonical = canonical_request(&sample_headers(), body);
        let lines: Vec<&str> = canonical.canonical_request.split('\n').collect();

        assert_eq!(lines[0], "POST");
        assert_eq!(lines[1], "/sessions");
        // Empty canonical query string.
        assert_eq!(lines[2], "");
        assert_eq!(lines[3], "content-type:application/json");
        assert_eq!(lines[6], "x-amz-x509:TUlJQg==");
        // The blank line that terminates the canonical headers.
        assert_eq!(lines[7], "");
        assert_eq!(lines[8], "content-type;host;x-amz-date;x-amz-x509");
        assert_eq!(lines[9], hex_sha256(body));
        assert_eq!(lines.len(), 10);
    }

    #[test]
    fn the_body_hash_covers_the_exact_bytes_sent() {
        // Whitespace differences change the hash, which is why the body is
        // serialized once and reused verbatim.
        let a = canonical_request(&sample_headers(), br#"{"a":1}"#);
        let b = canonical_request(&sample_headers(), br#"{"a": 1}"#);
        assert_ne!(a.canonical_request, b.canonical_request);
    }

    #[test]
    fn the_string_to_sign_has_four_lines_ending_in_the_request_hash() {
        let canonical = canonical_request(&sample_headers(), b"{}");
        let sts =
            string_to_sign(ALGORITHM_ECDSA_SHA256, TIMESTAMP, "us-east-1", &canonical).unwrap();
        let lines: Vec<&str> = sts.split('\n').collect();

        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "AWS4-X509-ECDSA-SHA256");
        assert_eq!(lines[1], "20260726T011500Z");
        assert_eq!(lines[2], "20260726/us-east-1/rolesanywhere/aws4_request");
        assert_eq!(lines[3], canonical.hash());
        // The hash of the canonical request is signed, not the request itself.
        assert!(!sts.contains("POST"));
    }

    #[test]
    fn empty_payloads_hash_to_the_known_sha256_of_the_empty_string() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn the_authorization_header_carries_the_serial_in_the_credential_field() {
        let header = authorization_header(
            ALGORITHM_ECDSA_SHA256,
            "4837201",
            "20260726/us-east-1/rolesanywhere/aws4_request",
            "content-type;host;x-amz-date",
            "3045abcd",
        );
        assert_eq!(
            header,
            "AWS4-X509-ECDSA-SHA256 \
             Credential=4837201/20260726/us-east-1/rolesanywhere/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, Signature=3045abcd"
        );
    }

    #[test]
    fn stripping_spaces_matches_the_helper_behavior() {
        assert_eq!(strip_excess_spaces("  a  b  "), "a b");
        assert_eq!(strip_excess_spaces("single"), "single");
        assert_eq!(strip_excess_spaces("   "), "");
        assert_eq!(strip_excess_spaces("a\tb"), "a\tb");
    }
}
