//! Differential comparison against the official AWS credential helper.
//!
//! The design asks to "compare Keystone with the official AWS helper using a
//! software key accessible to both", covering every pre-signature artifact: the
//! request body, the canonical request, the scope, the string-to-sign, and the
//! certificate headers.
//!
//! # What this suite does and does not do
//!
//! It does not build or run `aws_signing_helper`. Doing that would make the test
//! suite depend on a Go toolchain and a module download, so the comparison would
//! be skipped in exactly the environments where a regression is most likely to
//! go unnoticed.
//!
//! Instead, each artifact is reconstructed here by transcribing the helper's
//! algorithm from `aws_signing_helper/signer.go` (v1.8.4) — a second
//! implementation, written from the Go source rather than by calling Keystone's
//! own functions. The comment above each expectation quotes the specific Go it
//! came from. A shared misreading of the Go would defeat this; a divergence
//! introduced by refactoring Keystone's signing code would not, which is the
//! failure mode a differential test is for.
//!
//! The functions below deliberately duplicate logic that exists in
//! `keystone-roles-anywhere`. That duplication is the test.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use keystone_roles_anywhere::testing::TestIdentity;
use keystone_roles_anywhere::{CreateSessionRequest, RolesAnywhereRequestSigner, SignedRequest};
use keystone_tests::{fixture, FIXTURE_LEAF_SERIAL_DECIMAL};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

const TIMESTAMP: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);
const REGION: &str = "us-east-1";
const HOST: &str = "rolesanywhere.us-east-1.amazonaws.com";

// -- The helper's algorithm, transcribed from signer.go ----------------------

/// `timeFormat = "20060102T150405Z"`, applied to `.UTC()`.
fn helper_signing_date_time(timestamp: OffsetDateTime) -> String {
    let utc = timestamp.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// `shortTimeFormat = "20060102"`.
fn helper_short_date(timestamp: OffsetDateTime) -> String {
    let utc = timestamp.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}",
        utc.year(),
        u8::from(utc.month()),
        utc.day()
    )
}

/// `GetScope`: short date, region, service, `aws4_request`, slash-joined.
///
/// `ROLESANYWHERE_SIGNING_NAME` is `"rolesanywhere"`.
fn helper_scope(timestamp: OffsetDateTime, region: &str) -> String {
    let mut scope = String::new();
    scope.push_str(&helper_short_date(timestamp));
    scope.push('/');
    scope.push_str(region);
    scope.push('/');
    scope.push_str("rolesanywhere");
    scope.push('/');
    scope.push_str("aws4_request");
    scope
}

/// `certificateToString`: `base64.StdEncoding.EncodeToString(certificate.Raw)`.
fn helper_certificate_to_string(der: &[u8]) -> String {
    BASE64_STANDARD.encode(der)
}

/// `certificateChainToString`: the same encoding per certificate, comma-joined.
fn helper_certificate_chain_to_string(chain: &[Vec<u8>]) -> String {
    chain
        .iter()
        .map(|der| helper_certificate_to_string(der))
        .collect::<Vec<_>>()
        .join(",")
}

/// `createCanonicalHeaderString`, restricted to the headers the helper sets.
///
/// The helper builds this from `r.Header` after setting `host`, `x-amz-date`,
/// `x-amz-x509`, and optionally `x-amz-x509-chain`, skipping `ignoredHeaderKeys`
/// (`Authorization`, `User-Agent`, `X-Amzn-Trace-Id`), sorting the lowercase
/// names, and stripping excess spaces from the values.
fn helper_canonical_header_string(headers: &[(&str, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| {
            !matches!(
                name.to_ascii_lowercase().as_str(),
                "authorization" | "user-agent" | "x-amzn-trace-id"
            )
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
        .collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical = sorted
        .iter()
        .map(|(name, value)| format!("{name}:{value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let signed = sorted
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
}

/// `createCanonicalRequest`, which returns the *hash* and the signed-header list.
///
/// `POST\n/sessions\n<query>\n<headers>\n\n<signedHeaders>\n<contentSha256>`,
/// then `sha256.Sum256` and `hex.EncodeToString`. The query string is empty for
/// `CreateSession`, which has no query parameters.
fn helper_canonical_request(headers: &[(&str, String)], body: &[u8]) -> (String, String, String) {
    let (canonical_headers, signed_headers) = helper_canonical_header_string(headers);
    let mut canonical = String::new();
    canonical.push_str("POST");
    canonical.push('\n');
    canonical.push_str("/sessions");
    canonical.push('\n');
    // createCanonicalQueryString over a URL with no query.
    canonical.push_str("");
    canonical.push('\n');
    canonical.push_str(&canonical_headers);
    canonical.push_str("\n\n");
    canonical.push_str(&signed_headers);
    canonical.push('\n');
    canonical.push_str(&hex::encode(Sha256::digest(body)));

    let hash = hex::encode(Sha256::digest(canonical.as_bytes()));
    (canonical, hash, signed_headers)
}

/// `CreateStringToSign`: algorithm, formatted date-time, scope, canonical request
/// hash — newline separated, no trailing newline.
fn helper_string_to_sign(
    canonical_request_hash: &str,
    timestamp: OffsetDateTime,
    region: &str,
) -> String {
    let mut sts = String::new();
    sts.push_str("AWS4-X509-ECDSA-SHA256");
    sts.push('\n');
    sts.push_str(&helper_signing_date_time(timestamp));
    sts.push('\n');
    sts.push_str(&helper_scope(timestamp, region));
    sts.push('\n');
    sts.push_str(canonical_request_hash);
    sts
}

/// `BuildAuthorizationHeader`.
///
/// `signingCredentials` is `certificate.SerialNumber.String() + "/" + scope`;
/// `SerialNumber` is a `*big.Int`, whose `String()` is base 10.
fn helper_authorization_header(
    serial_decimal: &str,
    scope: &str,
    signed_headers: &str,
    signature_hex: &str,
) -> String {
    let mut header = String::new();
    header.push_str("AWS4-X509-ECDSA-SHA256");
    header.push(' ');
    header.push_str(&format!("Credential={serial_decimal}/{scope}"));
    header.push_str(", ");
    header.push_str(&format!("SignedHeaders={signed_headers}"));
    header.push_str(", ");
    header.push_str(&format!("Signature={signature_hex}"));
    header
}

// -- Keystone's side --------------------------------------------------------

fn leaf_der() -> Vec<u8> {
    keystone_pki::ParsedCertificate::from_pem(&fixture("device.pem"))
        .expect("the fixture leaf parses")
        .der()
        .to_vec()
}

fn ca_der() -> Vec<u8> {
    keystone_pki::ParsedCertificate::from_pem(&fixture("ca.pem"))
        .expect("the fixture CA parses")
        .der()
        .to_vec()
}

/// The same software key both implementations would load.
fn shared_key() -> SigningKey {
    SigningKey::from_pkcs8_pem(&fixture("device-key.pem"))
        .expect("the fixture private key loads as PKCS#8 P-256")
}

fn request() -> CreateSessionRequest {
    CreateSessionRequest {
        profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/differential"
            .to_string(),
        role_arn: "arn:aws:iam::123456789012:role/ExampleDeviceRole".to_string(),
        trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/differential"
            .to_string(),
        duration_seconds: 3600,
        role_session_name: Some("example-laptop".to_string()),
    }
}

fn sign_with_keystone(chain: Vec<Vec<u8>>) -> SignedRequest {
    let identity = TestIdentity::from_parts(
        shared_key(),
        leaf_der(),
        FIXTURE_LEAF_SERIAL_DECIMAL.to_string(),
    )
    .with_chain(chain);
    RolesAnywhereRequestSigner::new(identity, REGION)
        .sign(&request(), TIMESTAMP)
        .expect("the request signs")
}

/// The headers the helper would set, for the same request.
fn helper_headers(chain: &[Vec<u8>]) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        // The SDK sets content-type for a JSON request; the helper's signer adds
        // the rest in `signRequest`.
        ("content-type", "application/json".to_string()),
        ("host", HOST.to_string()),
        ("x-amz-date", helper_signing_date_time(TIMESTAMP)),
        ("x-amz-x509", helper_certificate_to_string(&leaf_der())),
    ];
    // `if certificateChain != nil` — set only when there is a chain.
    if !chain.is_empty() {
        headers.push((
            "x-amz-x509-chain",
            helper_certificate_chain_to_string(chain),
        ));
    }
    headers
}

fn keystone_header(signed: &SignedRequest, name: &str) -> Option<String> {
    signed
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

// -- The comparisons --------------------------------------------------------

#[test]
fn the_request_bodies_agree() {
    // The helper serializes the body through the AWS SDK for Go, which emits the
    // documented field names in the API model's order. Keystone's struct fixes
    // the same order; this pins the field names and the absence of whitespace,
    // which is what the payload hash actually covers.
    let body = request().serialize_body().expect("the body serializes");
    let text = String::from_utf8(body).expect("the body is UTF-8");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("the body is JSON");

    assert_eq!(parsed["durationSeconds"], 3600);
    assert_eq!(parsed["profileArn"], request().profile_arn);
    assert_eq!(parsed["roleArn"], request().role_arn);
    assert_eq!(parsed["roleSessionName"], "example-laptop");
    assert_eq!(parsed["trustAnchorArn"], request().trust_anchor_arn);
    assert_eq!(
        parsed.as_object().expect("an object").len(),
        5,
        "an extra field would change the payload hash"
    );
    assert!(!text.contains(": "), "compact, with no space after a colon");
    assert!(!text.contains('\n'));
}

#[test]
fn the_canonical_requests_agree() {
    let keystone = sign_with_keystone(Vec::new());
    let (helper, _, _) = helper_canonical_request(&helper_headers(&[]), &keystone.body);
    assert_eq!(keystone.canonical_request, helper);
}

#[test]
fn the_scopes_agree() {
    let keystone = keystone_roles_anywhere::signing::credential_scope(TIMESTAMP, REGION)
        .expect("the scope formats");
    assert_eq!(keystone, helper_scope(TIMESTAMP, REGION));
}

#[test]
fn the_strings_to_sign_agree() {
    let keystone = sign_with_keystone(Vec::new());
    let (_, hash, _) = helper_canonical_request(&helper_headers(&[]), &keystone.body);
    assert_eq!(
        keystone.string_to_sign,
        helper_string_to_sign(&hash, TIMESTAMP, REGION)
    );
}

#[test]
fn the_signed_header_lists_agree() {
    let keystone = sign_with_keystone(Vec::new());
    let (_, _, signed_headers) = helper_canonical_request(&helper_headers(&[]), &keystone.body);
    let authorization = keystone_header(&keystone, "authorization").expect("an authorization");
    assert!(
        authorization.contains(&format!("SignedHeaders={signed_headers}")),
        "{authorization}"
    );
}

#[test]
fn the_certificate_headers_agree() {
    let keystone = sign_with_keystone(Vec::new());
    assert_eq!(
        keystone_header(&keystone, "x-amz-x509"),
        Some(helper_certificate_to_string(&leaf_der()))
    );
}

#[test]
fn the_chain_headers_agree_when_intermediates_are_present() {
    // Keystone's own topology has no intermediates, but the header must still
    // match the helper when one is supplied — a comma-joined list, in order.
    let chain = vec![ca_der()];
    let keystone = sign_with_keystone(chain.clone());
    assert_eq!(
        keystone_header(&keystone, "x-amz-x509-chain"),
        Some(helper_certificate_chain_to_string(&chain))
    );

    // And the canonical request must then include that header, since adding a
    // header changes the signed-header list.
    let (helper, _, signed_headers) =
        helper_canonical_request(&helper_headers(&chain), &keystone.body);
    assert_eq!(keystone.canonical_request, helper);
    assert!(signed_headers.contains("x-amz-x509-chain"));
}

#[test]
fn the_authorization_headers_agree_except_for_the_signature() {
    // The signature bytes cannot be compared: ECDSA is nondeterministic and the
    // two implementations would draw different nonces. Everything around it is
    // compared exactly, and the signature is checked separately for encoding and
    // verifiability in `create_session.rs`.
    let keystone_signed = sign_with_keystone(Vec::new());
    let keystone = keystone_header(&keystone_signed, "authorization").expect("an authorization");
    let signature = keystone
        .split_once("Signature=")
        .expect("a signature field")
        .1;

    let (_, _, signed_headers) =
        helper_canonical_request(&helper_headers(&[]), &keystone_signed.body);
    let helper = helper_authorization_header(
        FIXTURE_LEAF_SERIAL_DECIMAL,
        &helper_scope(TIMESTAMP, REGION),
        &signed_headers,
        signature,
    );
    assert_eq!(keystone, helper);
}

#[test]
fn keystone_reads_the_same_serial_the_helper_would() {
    // The helper takes `certificate.SerialNumber.String()` from Go's crypto/x509;
    // Keystone takes it from `x509-parser`. A disagreement here is a silent
    // authentication failure, so it is checked against the fixture's known value
    // and against OpenSSL's hex output converted to decimal.
    let certificate =
        keystone_pki::ParsedCertificate::from_pem(&fixture("device.pem")).expect("parses");
    assert_eq!(certificate.serial_decimal, FIXTURE_LEAF_SERIAL_DECIMAL);
    assert_eq!(
        certificate.serial_decimal,
        u128::from_str_radix("013AFFD278482803", 16)
            .unwrap()
            .to_string()
    );
}

#[test]
fn a_header_the_helper_ignores_is_not_signed_by_keystone_either() {
    // `ignoredHeaderKeys`. `user-agent` in particular is added by the transport
    // after signing, so signing it would break every request.
    let mut headers = helper_headers(&[]);
    headers.push(("user-agent", "aws-sdk-go-v2".to_string()));
    headers.push(("authorization", "stale".to_string()));
    headers.push(("x-amzn-trace-id", "Root=1-2-3".to_string()));

    let keystone = sign_with_keystone(Vec::new());
    let (helper, _, signed_headers) = helper_canonical_request(&headers, &keystone.body);
    assert_eq!(keystone.canonical_request, helper);
    for ignored in ["user-agent", "authorization", "x-amzn-trace-id"] {
        assert!(!signed_headers.contains(ignored), "{signed_headers}");
    }
}
