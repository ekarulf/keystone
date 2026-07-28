//! Golden `CreateSession` signing artifacts.
//!
//! Everything the design's "Golden AWS signing tests" section calls for is
//! pinned here: a fixed software P-256 key, a fixed certificate, a fixed
//! timestamp, a fixed Region, a fixed request body, and fixed ARNs. What is
//! recorded is the canonical request, its hash, the string-to-sign, the
//! signed-header list, and the shape of the authorization header.
//!
//! The expected strings are literals rather than files updated by a `--bless`
//! flag. A blessable golden file records what the code does; a literal records
//! what the protocol requires, and the difference matters when the thing being
//! protected is a signature AWS has to accept.
//!
//! Per the design: "ECDSA may be nondeterministic, so verify signatures
//! cryptographically rather than requiring identical signature bytes." The
//! signature is therefore verified against the fixture's public key, and only
//! its encoding is asserted.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use keystone_roles_anywhere::signing::{hex_sha256, ALGORITHM_ECDSA_SHA256};
use keystone_roles_anywhere::testing::TestIdentity;
use keystone_roles_anywhere::{CreateSessionRequest, RolesAnywhereRequestSigner, SignedRequest};
use keystone_tests::{fixture, FIXTURE_LEAF_SERIAL_DECIMAL};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use time::OffsetDateTime;

/// The pinned signing time. Inside every fixture certificate's validity window.
const GOLDEN_TIMESTAMP: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);
const GOLDEN_REGION: &str = "us-east-1";

const GOLDEN_PROFILE_ARN: &str =
    "arn:aws:rolesanywhere:us-east-1:123456789012:profile/1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
const GOLDEN_ROLE_ARN: &str = "arn:aws:iam::123456789012:role/KeystonePersonalMac";
const GOLDEN_TRUST_ANCHOR_ARN: &str =
    "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0";
const GOLDEN_SESSION_NAME: &str = "erik-macbook";

/// The exact request body, byte for byte.
///
/// Field order is the AWS API's documented order, which `serialize_body` fixes
/// through the struct definition. The body is hashed into the canonical request,
/// so a reordering here would be a signature-breaking change.
const GOLDEN_BODY: &str = concat!(
    r#"{"durationSeconds":3600,"#,
    r#""profileArn":"arn:aws:rolesanywhere:us-east-1:123456789012:profile/1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","#,
    r#""roleArn":"arn:aws:iam::123456789012:role/KeystonePersonalMac","#,
    r#""roleSessionName":"erik-macbook","#,
    r#""trustAnchorArn":"arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"}"#,
);

const GOLDEN_SIGNED_HEADERS: &str = "content-type;host;x-amz-date;x-amz-x509";
const GOLDEN_SCOPE: &str = "20260726/us-east-1/rolesanywhere/aws4_request";
const GOLDEN_AMZ_DATE: &str = "20260726T011500Z";

/// Load the fixture key and certificate as a signing identity.
///
/// The certificate DER is what lands in `x-amz-x509`, and the serial in the
/// credential field, so both come from the same fixture file the differential
/// suite reads. The key is read from the same PKCS#8 PEM the official AWS helper
/// would load, which is what makes the comparison meaningful.
fn golden_identity() -> TestIdentity {
    let signing_key = SigningKey::from_pkcs8_pem(&fixture("device-key.pem"))
        .expect("the fixture private key loads as PKCS#8 P-256");
    TestIdentity::from_parts(
        signing_key,
        fixture_leaf_der(),
        FIXTURE_LEAF_SERIAL_DECIMAL.to_string(),
    )
}

/// The fixture leaf certificate, DER-encoded.
fn fixture_leaf_der() -> Vec<u8> {
    keystone_pki::ParsedCertificate::from_pem(&fixture("device.pem"))
        .expect("the fixture leaf parses")
        .der()
        .to_vec()
}

fn golden_request() -> CreateSessionRequest {
    CreateSessionRequest {
        profile_arn: GOLDEN_PROFILE_ARN.to_string(),
        role_arn: GOLDEN_ROLE_ARN.to_string(),
        trust_anchor_arn: GOLDEN_TRUST_ANCHOR_ARN.to_string(),
        duration_seconds: 3600,
        role_session_name: Some(GOLDEN_SESSION_NAME.to_string()),
    }
}

fn sign_golden() -> (SignedRequest, TestIdentity) {
    let identity = golden_identity();
    let signer = RolesAnywhereRequestSigner::new(&identity, GOLDEN_REGION);
    let signed = signer
        .sign(&golden_request(), GOLDEN_TIMESTAMP)
        .expect("the golden request signs");
    (signed, identity)
}

fn header<'a>(signed: &'a SignedRequest, name: &str) -> &'a str {
    signed
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("the signed request has no {name} header"))
}

#[test]
fn the_request_body_is_byte_for_byte_stable() {
    let body = golden_request()
        .serialize_body()
        .expect("the body serializes");
    assert_eq!(String::from_utf8(body).unwrap(), GOLDEN_BODY);
}

#[test]
fn the_body_that_was_hashed_is_the_body_that_is_sent() {
    // The whole point of `SignedRequest` carrying its own bytes: a re-serialized
    // body could differ and the signature would no longer cover it.
    let (signed, _) = sign_golden();
    assert_eq!(String::from_utf8(signed.body.clone()).unwrap(), GOLDEN_BODY);
    let hash_line = signed
        .canonical_request
        .lines()
        .last()
        .expect("the canonical request has lines");
    assert_eq!(hash_line, hex_sha256(&signed.body));
}

#[test]
fn the_canonical_request_matches_the_golden_text() {
    let (signed, _) = sign_golden();
    let expected = format!(
        "POST\n\
         /sessions\n\
         \n\
         content-type:application/json\n\
         host:rolesanywhere.us-east-1.amazonaws.com\n\
         x-amz-date:{GOLDEN_AMZ_DATE}\n\
         x-amz-x509:{certificate}\n\
         \n\
         {GOLDEN_SIGNED_HEADERS}\n\
         {body_hash}",
        certificate = BASE64_STANDARD.encode(fixture_leaf_der()),
        body_hash = hex_sha256(GOLDEN_BODY.as_bytes()),
    );
    assert_eq!(signed.canonical_request, expected);
}

#[test]
fn the_string_to_sign_carries_the_canonical_request_hash_and_not_the_request() {
    // The single most consequential detail in the port: the official helper's
    // `createCanonicalRequest` returns the *hash*, and `CreateStringToSign`
    // writes that. Putting the canonical request itself on line 4, or hashing it
    // twice, both produce a signature AWS rejects with an opaque error.
    let (signed, _) = sign_golden();
    let expected_hash = hex_sha256(signed.canonical_request.as_bytes());
    let expected =
        format!("{ALGORITHM_ECDSA_SHA256}\n{GOLDEN_AMZ_DATE}\n{GOLDEN_SCOPE}\n{expected_hash}");
    assert_eq!(signed.string_to_sign, expected);

    let lines: Vec<&str> = signed.string_to_sign.lines().collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[3].len(), 64, "line 4 is a hex SHA-256");
    assert_ne!(
        lines[3],
        hex_sha256(expected_hash.as_bytes()),
        "the hash must not be hashed a second time"
    );
}

#[test]
fn the_signed_header_list_is_recorded_and_ordered() {
    let (signed, _) = sign_golden();
    assert!(signed.canonical_request.contains(GOLDEN_SIGNED_HEADERS));
    assert!(header(&signed, "authorization")
        .contains(&format!("SignedHeaders={GOLDEN_SIGNED_HEADERS}")));

    // No chain header: the fixture leaf is issued directly by the trust anchor,
    // which is the ephemeral-CA topology. An empty header is not the same as an
    // absent one to AWS.
    assert!(
        !signed
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-amz-x509-chain")),
        "a leaf with no intermediates must not send an empty chain header"
    );
}

#[test]
fn the_certificate_header_is_standard_base64_der_with_no_pem_armor() {
    let (signed, _) = sign_golden();
    let encoded = header(&signed, "x-amz-x509");
    assert_eq!(encoded, BASE64_STANDARD.encode(fixture_leaf_der()));
    assert!(!encoded.contains("BEGIN"), "the header is DER, not PEM");
    assert!(!encoded.contains('\n'), "the header is a single line");
    // Standard alphabet with padding, matching the helper's
    // `base64.StdEncoding.EncodeToString(certificate.Raw)`.
    assert!(encoded.ends_with('=') || encoded.len().is_multiple_of(4));
    assert!(
        !encoded.contains('-') && !encoded.contains('_'),
        "not URL-safe base64"
    );
}

#[test]
fn the_authorization_header_has_the_documented_structure() {
    let (signed, _) = sign_golden();
    let authorization = header(&signed, "authorization");

    let (algorithm, rest) = authorization
        .split_once(' ')
        .expect("the algorithm is followed by a space");
    assert_eq!(algorithm, "AWS4-X509-ECDSA-SHA256");

    let parts: Vec<&str> = rest.split(", ").collect();
    assert_eq!(parts.len(), 3, "Credential, SignedHeaders, Signature");

    // The certificate serial in decimal occupies the position an access-key ID
    // holds in ordinary SigV4.
    assert_eq!(
        parts[0],
        format!("Credential={FIXTURE_LEAF_SERIAL_DECIMAL}/{GOLDEN_SCOPE}")
    );
    assert_eq!(parts[1], format!("SignedHeaders={GOLDEN_SIGNED_HEADERS}"));
    assert!(parts[2].starts_with("Signature="));
}

#[test]
fn the_certificate_serial_is_decimal_and_not_hex() {
    // 88664422113355779 == 0x013AFFD278482803. A hex serial in the credential
    // field is accepted by the header format and rejected by AWS.
    let (signed, _) = sign_golden();
    let credential = header(&signed, "authorization")
        .split_once("Credential=")
        .expect("a credential field")
        .1;
    let serial = credential.split('/').next().expect("a serial");
    assert_eq!(serial, "88664422113355779");
    assert_eq!(
        u128::from_str_radix("013AFFD278482803", 16)
            .unwrap()
            .to_string(),
        serial
    );
    assert!(
        serial.chars().all(|c| c.is_ascii_digit()),
        "the serial must be decimal"
    );
}

#[test]
fn the_signature_is_a_hex_der_ecdsa_signature_over_the_string_to_sign() {
    // Verified cryptographically rather than compared byte for byte, because
    // ECDSA nonces make the encoding nondeterministic.
    let (signed, identity) = sign_golden();
    let signature_hex = header(&signed, "authorization")
        .split_once("Signature=")
        .expect("a signature field")
        .1;

    assert!(
        signature_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "the signature is hex-encoded"
    );
    assert!(
        signature_hex.chars().all(|c| !c.is_ascii_uppercase()),
        "lowercase, matching Go's hex.EncodeToString"
    );

    let signature = hex::decode(signature_hex).expect("the signature decodes as hex");
    // DER SEQUENCE of two INTEGERs: ~70-72 bytes for P-256. A raw `r || s`
    // signature would be exactly 64 and would start with an arbitrary byte.
    assert_eq!(signature[0], 0x30, "DER SEQUENCE tag");
    assert_eq!(
        signature[1] as usize,
        signature.len() - 2,
        "the DER length covers the rest of the signature"
    );
    assert_ne!(signature.len(), 64, "DER, not raw r || s");

    assert!(
        identity.verify(signed.string_to_sign.as_bytes(), &signature),
        "the signature verifies over the string-to-sign, hashed once with SHA-256"
    );
    // The negative half of "do not hash twice": a signature made over the
    // *digest* of the string-to-sign would not verify over the string itself.
    assert!(
        !identity.verify(
            hex_sha256(signed.string_to_sign.as_bytes()).as_bytes(),
            &signature
        ),
        "the signed message is the string-to-sign, not its hash"
    );
}

#[test]
fn two_signings_of_the_same_request_agree_on_everything_but_the_signature() {
    let (first, _) = sign_golden();
    let (second, _) = sign_golden();
    assert_eq!(first.canonical_request, second.canonical_request);
    assert_eq!(first.string_to_sign, second.string_to_sign);
    assert_eq!(first.body, second.body);
    // The signature may or may not differ — the point is that nothing else does.
}

#[test]
fn a_request_without_a_session_name_omits_the_field_entirely() {
    // A `"roleSessionName":null` would change the body hash and is not what the
    // API documents for an absent session name.
    let mut request = golden_request();
    request.role_session_name = None;
    let body = String::from_utf8(request.serialize_body().unwrap()).unwrap();
    assert!(!body.contains("essionName"), "{body}");
    assert!(body.contains(r#""roleArn""#));
}
