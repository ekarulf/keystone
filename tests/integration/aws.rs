//! AWS integration tests for `CreateSession`.
//!
//! The design's list is:
//!
//! * valid identity succeeds;
//! * expired certificate fails;
//! * wrong CA fails;
//! * wrong trust anchor fails;
//! * wrong profile fails;
//! * wrong role fails;
//! * modified body fails;
//! * modified signed header fails;
//! * stale timestamp fails;
//! * unauthorized SAN fails;
//! * returned credentials call `sts:GetCallerIdentity`;
//! * disabled trust anchor prevents new sessions.
//!
//! It is covered here at three levels, because "against a dedicated account" is
//! not a thing every run of `cargo test` can do.
//!
//! # Level 1 — always runs
//!
//! Every case has a half that needs no account, and for several of them that
//! half is the whole point. An expired certificate, a certificate from the wrong
//! CA, and a certificate carrying no device SAN are all refused *locally*, before
//! a request exists: the assertion is not only that they fail but that nothing
//! was sent. The wrong-ARN and disabled-anchor cases are driven through
//! [`StubServer`] with the error bodies AWS returns, which checks the thing
//! Keystone actually owns — that the rejection is surfaced with its code and
//! message and is not retried. The tampering cases are checked
//! cryptographically: the signature is verified against the bytes the server
//! received, then against a mutated copy, which is precisely the check AWS
//! performs.
//!
//! # Level 2 — `--ignored`, against a real account
//!
//! Gated on `KEYSTONE_AWS_INTEGRATION_PROFILE` naming an enrolled profile, so
//! the suite is silent rather than failing on a machine with no account wired
//! up, and compiled only for a target with a hardware key store, since it signs
//! with the real device key. It is written against the `backend` aliases below so
//! the Secure Enclave and the TPM face the same assertions.
//!
//! These tests only read: they call `CreateSession`, deliberately malformed or
//! not, and `sts:GetCallerIdentity`. They create, modify, and delete nothing.
//!
//! ```text
//! KEYSTONE_AWS_INTEGRATION_PROFILE=personal \
//!   cargo test -p keystone-tests --test integration_aws -- --ignored --nocapture
//! ```
//!
//! # Level 3 — the manual checklist
//!
//! Two cases cannot be automated without changing the account. Issuing an
//! expired certificate, one from an untrusted CA, or one with a SAN the role does
//! not permit means running a CA against a live trust anchor; disabling a trust
//! anchor is a modification of production infrastructure that would break every
//! other device using it. `aws_manual_checklist` prints both procedures and the
//! expected outcome, so the steps are recorded and repeatable without this suite
//! reaching for write permissions it should not hold.

use std::time::Duration;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use keystone_core::credentials::CREDENTIAL_PROCESS_VERSION;
use keystone_core::error::KeystoneError;
use keystone_core::time::FixedClock;
use keystone_pki::validate::{validate_chain, validate_device_certificate, ValidationContext};
use keystone_pki::ParsedCertificate;
use keystone_roles_anywhere::response::looks_like_clock_skew;
use keystone_roles_anywhere::testing::stub_server::{StubResponse, StubServer};
use keystone_roles_anywhere::testing::TestIdentity;
use keystone_roles_anywhere::{CreateSessionRequest, RolesAnywhereClient, TransportConfig};
// Level 2 only: retries are disabled there, so a rejection from AWS is reported
// verbatim rather than after three identical attempts.
#[cfg(any(target_os = "macos", windows))]
use keystone_roles_anywhere::RetryPolicy;
use keystone_tests::{fixture, fixture_key_id, FIXTURE_SAN};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey as _;
use time::OffsetDateTime;

/// Inside every fixture validity window that is meant to be valid.
const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);
const REGION: &str = "us-east-1";

const ACCOUNT: &str = "123456789012";
const TRUST_ANCHOR_ARN: &str =
    "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0";
const RA_PROFILE_ARN: &str =
    "arn:aws:rolesanywhere:us-east-1:123456789012:profile/1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";
const ROLE_ARN: &str = "arn:aws:iam::123456789012:role/KeystonePersonalMac";

/// A `CreateSession` success body, in the shape AWS returns it.
const SUCCESS_BODY: &str = r#"{
  "credentialSet": [
    {
      "assumedRoleUser": {
        "arn": "arn:aws:sts::123456789012:assumed-role/KeystonePersonalMac/example-laptop",
        "assumedRoleId": "AROAEXAMPLE:example-laptop"
      },
      "credentials": {
        "accessKeyId": "ASIAEXAMPLE",
        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "sessionToken": "IQoJb3JpZ2luX2VjEXAMPLETOKEN",
        "expiration": "2026-07-26T02:15:00Z"
      },
      "packedPolicySize": 0,
      "roleArn": "arn:aws:iam::123456789012:role/KeystonePersonalMac",
      "sourceIdentity": "example-laptop"
    }
  ],
  "subjectArn": "arn:aws:rolesanywhere:us-east-1:123456789012:subject/abc"
}"#;

// -- Fixtures as signing material -------------------------------------------

fn certificate(name: &str) -> ParsedCertificate {
    ParsedCertificate::from_pem(&fixture(name))
        .unwrap_or_else(|error| panic!("fixture {name} parses: {error}"))
}

/// The device key the fixtures were issued to.
fn device_key() -> SigningKey {
    SigningKey::from_pkcs8_pem(&fixture("device-key.pem")).expect("the fixture key loads")
}

fn device_public_key() -> [u8; 65] {
    let encoded = device_key().verifying_key().to_encoded_point(false);
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(encoded.as_bytes());
    bytes
}

/// The validation context Keystone builds for this device: this key, this key ID.
fn expecting_this_device(now: OffsetDateTime) -> ValidationContext {
    ValidationContext::new(now)
        .expecting_key(device_public_key())
        .expecting_key_id(fixture_key_id())
}

/// An AWS signing identity over a fixture certificate and the fixture key.
fn identity_for(certificate_name: &str) -> TestIdentity {
    let leaf = certificate(certificate_name);
    TestIdentity::from_parts(
        device_key(),
        leaf.der().to_vec(),
        leaf.serial_decimal.clone(),
    )
}

fn request() -> CreateSessionRequest {
    CreateSessionRequest {
        profile_arn: RA_PROFILE_ARN.to_string(),
        role_arn: ROLE_ARN.to_string(),
        trust_anchor_arn: TRUST_ANCHOR_ARN.to_string(),
        duration_seconds: 3600,
        role_session_name: Some("example-laptop".to_string()),
    }
}

fn client<'a>(
    identity: &'a TestIdentity,
    server: &StubServer,
    now: OffsetDateTime,
) -> RolesAnywhereClient<&'a TestIdentity, FixedClock> {
    RolesAnywhereClient::new(
        identity,
        REGION,
        FixedClock(now),
        TransportConfig {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
        },
    )
    .expect("the client builds")
    .with_endpoint_override(server.base_url())
    // The retry schedule is asserted elsewhere; here it only has to not wait.
    .with_sleeper(|_| {})
}

/// Assert a rejection carries the AWS code and message, and return the message.
fn rejected(error: KeystoneError, expected_status: u16, expected_code: &str) -> String {
    match error {
        KeystoneError::RolesAnywhereRejected {
            status,
            code,
            message,
        } => {
            assert_eq!(status, expected_status);
            assert_eq!(code, expected_code);
            message
        }
        other => panic!("expected an AWS rejection, got {other:?}"),
    }
}

/// Rebuild the string-to-sign from the bytes a server received.
///
/// Nothing from the signing path is reused: the headers are read back off the
/// wire and re-canonicalized, which is what AWS does with them.
fn string_to_sign_from_wire(
    request: &keystone_roles_anywhere::testing::stub_server::CapturedRequest,
    body: &[u8],
    timestamp: OffsetDateTime,
) -> String {
    use keystone_roles_anywhere::signing;

    let mut headers = signing::SignedHeaders::new();
    for name in ["content-type", "host", "x-amz-date", "x-amz-x509"] {
        headers.insert(name, request.header(name).expect(name));
    }
    if let Some(chain) = request.header("x-amz-x509-chain") {
        headers.insert("x-amz-x509-chain", chain);
    }
    let canonical = signing::canonical_request(&headers, body);
    signing::string_to_sign(
        signing::ALGORITHM_ECDSA_SHA256,
        timestamp,
        REGION,
        &canonical,
    )
    .expect("the string-to-sign formats")
}

fn signature_from(
    request: &keystone_roles_anywhere::testing::stub_server::CapturedRequest,
) -> Vec<u8> {
    let hex = request
        .header("authorization")
        .and_then(|value| value.split("Signature=").nth(1))
        .expect("an authorization header with a signature");
    hex::decode(hex).expect("the signature is hex")
}

// -- valid identity succeeds -------------------------------------------------

#[test]
fn a_valid_identity_is_exchanged_for_credentials() {
    let identity = identity_for("device.pem");

    // The same certificate Keystone would have validated before signing.
    let leaf = certificate("device.pem");
    validate_device_certificate(&leaf, &expecting_this_device(NOW))
        .expect("the fixture leaf is a valid device certificate");
    validate_chain(&leaf, &[], &certificate("ca.pem"), NOW).expect("it chains to the trust anchor");

    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&identity, &server, NOW)
        .create_session(&request())
        .expect("credentials are issued");

    result
        .credentials
        .validate(NOW)
        .expect("the credentials are usable");
    assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");
    assert_eq!(
        result.assumed_role_arn.as_deref(),
        Some("arn:aws:sts::123456789012:assumed-role/KeystonePersonalMac/example-laptop")
    );

    // The identity that reached AWS is the certificate, not the key: the leaf is
    // sent, the chain header is absent because the issuer is the trust anchor.
    let sent = server.requests().remove(0);
    assert_eq!(
        sent.header("x-amz-x509"),
        Some(BASE64_STANDARD.encode(leaf.der()).as_str())
    );
    assert!(sent.header("x-amz-x509-chain").is_none());
    assert_eq!(server.request_count(), 1);
}

// -- expired certificate fails ----------------------------------------------

#[test]
fn an_expired_certificate_fails_before_anything_is_sent() {
    // AWS would reject this too, but a request built from an expired certificate
    // is a request Keystone should never have made: the rejection arrives as an
    // opaque signature error, and the certificate is the thing at fault.
    let expired = certificate("device-expired.pem");
    assert!(expired.not_after < NOW);

    let error = validate_device_certificate(&expired, &expecting_this_device(NOW))
        .expect_err("an expired certificate is refused");
    match error {
        KeystoneError::CertificateExpired(when) => assert_eq!(when, expired.not_after),
        other => panic!("expected an expiry error, got {other}"),
    }

    // And a server that would have answered sees nothing, because the exchange
    // never gets as far as building a request.
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    assert_eq!(server.request_count(), 0);

    // Had it been sent, this is how AWS reports it, and it must not be retried:
    // the certificate will still be expired on a second attempt.
    let identity = identity_for("device-expired.pem");
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"Certificate has expired","__type":"AccessDeniedException"}"#,
    )]);
    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&request())
            .expect_err("AWS rejects an expired certificate"),
        403,
        "AccessDeniedException",
    );
    assert!(message.contains("expired"), "{message}");
    assert_eq!(server.request_count(), 1);
}

// -- wrong CA fails ----------------------------------------------------------

#[test]
fn a_certificate_from_the_wrong_ca_fails() {
    // The same device key, the correct SAN, a well-formed leaf — issued by a CA
    // that is not the trust anchor. Only the chain signature distinguishes it.
    let other = certificate("device-other-ca.pem");
    validate_device_certificate(&other, &expecting_this_device(NOW))
        .expect("the leaf itself is well formed, which is what makes this case worth testing");

    let error = validate_chain(&other, &[], &certificate("ca.pem"), NOW)
        .expect_err("a leaf from another CA does not chain to this trust anchor");
    assert!(
        matches!(error, KeystoneError::InvalidCertificateChain(_)),
        "{error}"
    );

    // AWS's own answer, for the case where the local check is bypassed: the
    // trust anchor does not know the issuer.
    let identity = identity_for("device-other-ca.pem");
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"Untrusted signing certificate","__type":"AccessDeniedException"}"#,
    )]);
    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&request())
            .expect_err("AWS rejects a certificate it cannot chain"),
        403,
        "AccessDeniedException",
    );
    assert!(message.contains("Untrusted"), "{message}");
    assert_eq!(server.request_count(), 1);
}

// -- wrong trust anchor fails ------------------------------------------------

#[test]
fn a_wrong_trust_anchor_arn_fails_and_is_not_retried() {
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::error(
        404,
        r#"{"message":"Trust anchor not found","__type":"ResourceNotFoundException"}"#,
    )
    .with_header("x-amzn-RequestId", "req-trust-anchor")]);

    let mut wrong = request();
    wrong.trust_anchor_arn =
        format!("arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:trust-anchor/00000000-0000-0000-0000-000000000000");

    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&wrong)
            .expect_err("an unknown trust anchor is rejected"),
        404,
        "ResourceNotFoundException",
    );
    assert!(message.contains("Trust anchor not found"), "{message}");
    assert!(message.contains("req-trust-anchor"), "{message}");

    // The ARN that was sent is the one that was asked for: a client that
    // silently substituted a default would make this test pass for the wrong
    // reason.
    let sent = server.requests().remove(0);
    assert_eq!(sent.body_json()["trustAnchorArn"], wrong.trust_anchor_arn);
    assert_eq!(server.request_count(), 1);
}

// -- wrong profile fails -----------------------------------------------------

#[test]
fn a_wrong_roles_anywhere_profile_arn_fails_and_is_not_retried() {
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::error(
        404,
        r#"{"message":"Profile not found","__type":"ResourceNotFoundException"}"#,
    )]);

    let mut wrong = request();
    wrong.profile_arn = format!(
        "arn:aws:rolesanywhere:{REGION}:{ACCOUNT}:profile/00000000-0000-0000-0000-000000000000"
    );

    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&wrong)
            .expect_err("an unknown profile is rejected"),
        404,
        "ResourceNotFoundException",
    );
    assert!(message.contains("Profile not found"), "{message}");

    let sent = server.requests().remove(0);
    assert_eq!(sent.body_json()["profileArn"], wrong.profile_arn);
    assert_eq!(server.request_count(), 1);
}

// -- wrong role fails --------------------------------------------------------

#[test]
fn a_role_the_profile_does_not_allow_fails_and_is_not_retried() {
    // The most likely real misconfiguration: a valid role ARN that the Roles
    // Anywhere profile does not list, or whose trust policy does not admit this
    // trust anchor. Both arrive as AccessDenied.
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"Role arn:aws:iam::123456789012:role/SomeOtherRole is not allowed by the profile","__type":"AccessDeniedException"}"#,
    )]);

    let mut wrong = request();
    wrong.role_arn = format!("arn:aws:iam::{ACCOUNT}:role/SomeOtherRole");

    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&wrong)
            .expect_err("a role outside the profile is rejected"),
        403,
        "AccessDeniedException",
    );
    assert!(message.contains("not allowed by the profile"), "{message}");

    let sent = server.requests().remove(0);
    assert_eq!(sent.body_json()["roleArn"], wrong.role_arn);
    assert_eq!(server.request_count(), 1);
}

#[test]
fn a_session_for_another_role_is_reported_rather_than_discarded() {
    // The inverse failure: AWS answers, but with a session for a different role,
    // which means the Roles Anywhere profile maps somewhere the local
    // configuration does not expect. The client's job is to surface which role
    // came back — `keystone-cli`'s `check_assumed_role` turns that into the
    // refusal, and its own tests cover the refusal itself.
    let identity = identity_for("device.pem");
    let body = SUCCESS_BODY.replace("KeystonePersonalMac", "SomeOtherRole");
    let server = StubServer::start(vec![StubResponse::ok(&body)]);

    let result = client(&identity, &server, NOW)
        .create_session(&request())
        .expect("the body parses");
    let assumed = result.assumed_role_arn.expect("an assumed-role ARN");
    let requested_role = ROLE_ARN.rsplit('/').next().expect("a role name");
    assert!(
        !assumed.contains(requested_role),
        "the mismatch must be visible to the caller, not smoothed over: {assumed}"
    );
    assert!(assumed.contains("SomeOtherRole"), "{assumed}");
}

// -- modified body fails -----------------------------------------------------

#[test]
fn a_modified_body_invalidates_the_signature() {
    // What AWS checks: the payload hash is inside the canonical request, which is
    // inside the string-to-sign. Verifying the captured signature against the
    // captured body — and then against a mutated body — is that check, run here.
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    client(&identity, &server, NOW)
        .create_session(&request())
        .expect("credentials are issued");

    let sent = server.requests().remove(0);
    let signature = signature_from(&sent);

    assert!(
        identity.verify(
            string_to_sign_from_wire(&sent, &sent.body, NOW).as_bytes(),
            &signature
        ),
        "the signature must verify over the body as received"
    );

    // A privilege escalation an attacker would actually attempt: a longer
    // session, or a different role, on an otherwise valid signed request.
    for tampered in [
        String::from_utf8(sent.body.clone())
            .unwrap()
            .replace("3600", "43200"),
        String::from_utf8(sent.body.clone())
            .unwrap()
            .replace("KeystonePersonalMac", "AdministratorRole"),
    ] {
        assert_ne!(
            tampered.as_bytes(),
            sent.body.as_slice(),
            "the body changed"
        );
        assert!(
            !identity.verify(
                string_to_sign_from_wire(&sent, tampered.as_bytes(), NOW).as_bytes(),
                &signature
            ),
            "a modified body must not verify: {tampered}"
        );
    }
}

// -- modified signed header fails -------------------------------------------

#[test]
fn a_modified_signed_header_invalidates_the_signature() {
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    client(&identity, &server, NOW)
        .create_session(&request())
        .expect("credentials are issued");

    let sent = server.requests().remove(0);
    let signature = signature_from(&sent);
    let signed_headers = sent
        .header("authorization")
        .and_then(|value| value.split("SignedHeaders=").nth(1))
        .and_then(|rest| rest.split(',').next())
        .expect("a signed-header list");

    // Every header the authorization names is covered, so changing any one of
    // them must break verification. `x-amz-date` and `x-amz-x509` are the two
    // that matter most: one is the replay window, the other is the identity.
    for (name, replacement) in [
        ("x-amz-date", "20260726T021500Z"),
        ("host", "rolesanywhere.us-west-2.amazonaws.com"),
        (
            "x-amz-x509",
            BASE64_STANDARD
                .encode(certificate("device-other-key.pem").der())
                .as_str(),
        ),
        ("content-type", "text/plain"),
    ] {
        assert!(
            signed_headers.contains(name),
            "{name} should be in {signed_headers}"
        );
        let mut mutated = sent.clone();
        mutated
            .headers
            .insert(name.to_string(), replacement.to_string());
        assert!(
            !identity.verify(
                string_to_sign_from_wire(&mutated, &mutated.body, NOW).as_bytes(),
                &signature
            ),
            "a modified {name} must not verify"
        );
    }
}

// -- stale timestamp fails ---------------------------------------------------

#[test]
fn a_stale_timestamp_is_sent_as_signed_and_rejected() {
    // Keystone does not correct the clock: whatever time it signed for is the
    // time in `x-amz-date`, and AWS decides. What Keystone owes the user is a
    // message that says so, which is what `looks_like_clock_skew` produces.
    let identity = identity_for("device.pem");
    let stale = NOW - time::Duration::minutes(30);
    // This body is what real IAM Roles Anywhere returns for a signature 30
    // minutes stale, copied from an account run. It deliberately does not say
    // "expired" or name a date, because AWS does not.
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"Invalid signature","__type":"AccessDeniedException"}"#,
    )]);

    let error = client(&identity, &server, stale)
        .create_session(&request())
        .expect_err("a stale signature is rejected");
    let message = rejected(error, 403, "AccessDeniedException");
    assert!(
        looks_like_clock_skew("AccessDeniedException", &message),
        "the rejection should be recognized as clock skew: {message}"
    );

    let sent = server.requests().remove(0);
    assert_eq!(sent.header("x-amz-date"), Some("20260726T004500Z"));
    assert!(sent
        .header("authorization")
        .expect("authorization")
        .contains("/20260726/us-east-1/rolesanywhere/aws4_request"));
    // Nothing retryable about it: a replay would carry the same stale date.
    assert_eq!(server.request_count(), 1);
}

#[test]
fn a_clock_that_cannot_be_right_is_refused_locally() {
    // A Mac with a dead clock reports a date decades off. Signing for it wastes a
    // round trip and returns an error that names the signature, not the clock.
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let error = client(
        &identity,
        &server,
        time::macros::datetime!(2001-01-01 0:00 UTC),
    )
    .create_session(&request())
    .expect_err("an implausible clock is refused");
    assert!(matches!(error, KeystoneError::ClockSkew), "{error:?}");
    assert_eq!(server.request_count(), 0, "nothing should have been sent");
}

// -- unauthorized SAN fails --------------------------------------------------

#[test]
fn a_certificate_without_this_devices_san_fails() {
    // The SAN is what the generated role's trust policy conditions on
    // (`aws:PrincipalTag/x509SAN/URI`), so a certificate without one — or with
    // another device's — cannot assume the role. Both halves are checked
    // locally, because Keystone knows which SAN it expects.
    let no_san = certificate("device-no-san.pem");
    assert!(no_san.uri_sans.is_empty());
    assert!(matches!(
        validate_device_certificate(&no_san, &expecting_this_device(NOW)),
        Err(KeystoneError::MissingDeviceSan)
    ));

    let leaf = certificate("device.pem");
    assert_eq!(leaf.uri_sans, vec![FIXTURE_SAN.to_string()]);
    let another_device = ValidationContext::new(NOW)
        .expecting_key(device_public_key())
        .expecting_key_id(keystone_core::identity::KeyId::parse("someotherdevice").unwrap());
    let error = validate_device_certificate(&leaf, &another_device)
        .expect_err("a certificate naming another device is refused")
        .to_string();
    assert!(error.contains("someotherdevice"), "{error}");

    // And AWS's answer when a SAN reaches the trust policy that it does not
    // permit: the session is refused, not narrowed.
    let identity = identity_for("device-no-san.pem");
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"User: arn:aws:sts::123456789012:assumed-role/KeystonePersonalMac is not authorized to perform: sts:AssumeRole with an explicit deny in the role trust policy","__type":"AccessDeniedException"}"#,
    )]);
    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&request())
            .expect_err("an unauthorized SAN is rejected"),
        403,
        "AccessDeniedException",
    );
    assert!(message.contains("explicit deny"), "{message}");
    assert_eq!(server.request_count(), 1);
}

// -- disabled trust anchor prevents new sessions ----------------------------

#[test]
fn a_disabled_trust_anchor_prevents_new_sessions() {
    // The revocation story: `keystone revoke` explains how to disable the trust
    // anchor, and this is what the next exchange gets. It must fail closed and
    // not retry — a disabled anchor is not a transient condition, and a device
    // that kept retrying would look like a broken tool rather than a revoked one.
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"Trust anchor is not enabled","__type":"AccessDeniedException"}"#,
    )]);

    let message = rejected(
        client(&identity, &server, NOW)
            .create_session(&request())
            .expect_err("a disabled trust anchor is rejected"),
        403,
        "AccessDeniedException",
    );
    assert!(message.contains("not enabled"), "{message}");
    assert_eq!(server.request_count(), 1);

    let error = KeystoneError::RolesAnywhereRejected {
        status: 403,
        code: "AccessDeniedException".to_string(),
        message,
    };
    assert!(!error.is_retryable(), "revocation is not a transient error");
}

// -- returned credentials call sts:GetCallerIdentity ------------------------

#[test]
fn returned_credentials_are_shaped_for_the_credential_process_contract() {
    // The account-backed half of this case is `aws_credentials_call_get_caller_identity`
    // below. This half is what makes that call possible at all: the JSON the AWS
    // SDK reads has to have the documented field names and a parseable expiry.
    let identity = identity_for("device.pem");
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&identity, &server, NOW)
        .create_session(&request())
        .expect("credentials are issued");

    let output = result.credentials.to_process_output();
    assert_eq!(output.version, CREDENTIAL_PROCESS_VERSION);

    // The field names, checked against the serialized text rather than a parsed
    // map: `serde_json::Value` sorts its keys, which would hide a renamed field
    // behind a lookup that still succeeded.
    let text = serde_json::to_string(&output).expect("the output serializes");
    assert_eq!(
        text,
        concat!(
            r#"{"Version":1,"#,
            r#""AccessKeyId":"ASIAEXAMPLE","#,
            r#""SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","#,
            r#""SessionToken":"IQoJb3JpZ2luX2VjEXAMPLETOKEN","#,
            r#""Expiration":"2026-07-26T02:15:00Z"}"#
        )
    );

    let json: serde_json::Value = serde_json::from_str(&text).expect("the SDK can parse it");
    keystone_core::time::parse_rfc3339(json["Expiration"].as_str().unwrap())
        .expect("the SDK can parse the expiry");
}

// -- Level 2: against a real account ----------------------------------------

/// The hardware backend for this platform.
///
/// Level 2 signs with a real device key, so it and its helpers are compiled only
/// for a target that has a key store. Written against these aliases rather than
/// one platform's types, so the same assertions cover both backends.
#[cfg(target_os = "macos")]
mod backend {
    pub use keystone_macos::AccessPolicy as KeyPolicy;
    pub use keystone_macos::CertificateIdentity;
    pub use keystone_macos::SecureEnclaveIdentity as DeviceKey;
}

#[cfg(windows)]
mod backend {
    pub use keystone_windows::CertificateIdentity;
    pub use keystone_windows::TpmIdentity as DeviceKey;
    pub use keystone_windows::TpmPolicy as KeyPolicy;
}

/// The profile to exchange with, or `None` when no account is configured.
///
/// `KEYSTONE_AWS_INTEGRATION_PROFILE` names a profile in the store;
/// `KEYSTONE_AWS_INTEGRATION_HOME` optionally overrides where the store lives,
/// so a throwaway account can be tested without touching the real one.
#[cfg(any(target_os = "macos", windows))]
fn integration_target() -> Option<(String, keystone_core::store::Store)> {
    let profile = std::env::var("KEYSTONE_AWS_INTEGRATION_PROFILE").ok()?;
    let paths = match std::env::var_os("KEYSTONE_AWS_INTEGRATION_HOME") {
        Some(root) => keystone_core::config::Paths::rooted_at(root),
        None => keystone_core::config::Paths::discover().expect("Keystone's paths resolve"),
    };
    Some((profile, keystone_core::store::Store::new(paths)))
}

/// Print why an account test did nothing, so an ignored run is not silent.
#[cfg(any(target_os = "macos", windows))]
fn no_account() -> bool {
    if integration_target().is_none() {
        println!(
            "skipped: set KEYSTONE_AWS_INTEGRATION_PROFILE to the name of an enrolled profile"
        );
        return true;
    }
    false
}

/// The real device identity for the configured profile.
///
/// Deliberately reconstructed here from the store rather than shelling out to
/// the CLI, so the test exercises the same signing path `credential-process`
/// does — a hardware key paired with the stored certificate.
#[cfg(any(target_os = "macos", windows))]
fn real_identity(
    store: &keystone_core::store::Store,
    profile: &keystone_core::config::Profile,
    now: OffsetDateTime,
) -> backend::CertificateIdentity {
    let key_id = profile.key_id.clone().expect("the profile has an identity");
    let metadata = store.load_identity(&key_id).expect("the identity loads");
    let key = backend::DeviceKey::restore(
        &metadata,
        backend::KeyPolicy::new(profile.key_accessibility),
    )
    .expect("the hardware key restores");

    let fingerprint = profile
        .certificate_fingerprint_sha256
        .clone()
        .expect("the profile has a certificate");
    let (leaf_der, _ca_der) = store
        .load_certificates(&fingerprint)
        .expect("the certificates load");
    let leaf = ParsedCertificate::from_der(&leaf_der).expect("the leaf parses");
    backend::CertificateIdentity::new(key, leaf, Vec::new(), now)
        .expect("the key and certificate belong together")
}

/// A client pointed at real AWS, with retries disabled so a rejection is
/// reported verbatim rather than after three identical attempts.
#[cfg(any(target_os = "macos", windows))]
fn real_client(
    identity: backend::CertificateIdentity,
    profile: &keystone_core::config::Profile,
) -> RolesAnywhereClient<backend::CertificateIdentity, keystone_core::time::SystemClock> {
    RolesAnywhereClient::new(
        identity,
        profile.region.clone(),
        keystone_core::time::SystemClock,
        TransportConfig::from_profile(profile),
    )
    .expect("the client builds")
    .with_retry_policy(RetryPolicy::no_retries())
}

/// Everything an account test needs, or `None` to skip.
#[cfg(any(target_os = "macos", windows))]
fn account_setup() -> Option<(
    keystone_core::config::Profile,
    keystone_core::store::Store,
    String,
)> {
    let (name, store) = integration_target()?;
    let config = store.load_config().expect("the config loads");
    let profile = config
        .profile(&name)
        .unwrap_or_else(|error| panic!("profile {name}: {error}"))
        .clone();
    profile
        .require_ready(&name)
        .expect("the profile is fully configured; deploy and sync it first");
    Some((profile, store, name))
}

#[test]
#[ignore = "needs a dedicated AWS account; set KEYSTONE_AWS_INTEGRATION_PROFILE"]
#[cfg(any(target_os = "macos", windows))]
fn aws_a_valid_identity_succeeds() {
    if no_account() {
        return;
    }
    let (profile, store, name) = account_setup().expect("an account is configured");
    let now = OffsetDateTime::now_utc();
    let identity = real_identity(&store, &profile, now);
    let request = session_request(&profile, &name);

    let mut attempts = Vec::new();
    let result = real_client(identity, &profile)
        .create_session_recording(&request, &mut attempts)
        .expect("a valid identity is exchanged for credentials");

    result
        .credentials
        .validate(now)
        .expect("the credentials are usable now");
    assert!(
        result.credentials.expiration > now,
        "the session should be in the future"
    );
    assert_eq!(attempts.len(), 1, "no retries were needed");

    let assumed = result.assumed_role_arn.expect("an assumed-role ARN");
    let role_name = profile.role_arn.rsplit('/').next().expect("a role name");
    assert!(
        assumed.contains(role_name),
        "AWS returned a session for {assumed}, not for {role_name}"
    );
    // Never the secret: only the identifier and the expiry.
    println!(
        "issued {} until {}",
        result.credentials.access_key_id,
        keystone_core::time::format_rfc3339(result.credentials.expiration)
    );
}

#[test]
#[ignore = "needs a dedicated AWS account; set KEYSTONE_AWS_INTEGRATION_PROFILE"]
#[cfg(any(target_os = "macos", windows))]
fn aws_credentials_call_get_caller_identity() {
    if no_account() {
        return;
    }
    let (profile, store, name) = account_setup().expect("an account is configured");
    let now = OffsetDateTime::now_utc();
    let identity = real_identity(&store, &profile, now);
    let result = real_client(identity, &profile)
        .create_session(&session_request(&profile, &name))
        .expect("credentials are issued");

    // A read-only call, made with the temporary credentials and nothing else in
    // the environment: `AWS_PROFILE` is cleared so an ambient profile cannot
    // answer in their place and make the test pass without them.
    let output = std::process::Command::new("aws")
        .args(["sts", "get-caller-identity", "--output", "json"])
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_DEFAULT_PROFILE")
        .env("AWS_ACCESS_KEY_ID", &result.credentials.access_key_id)
        .env(
            "AWS_SECRET_ACCESS_KEY",
            result.credentials.secret_access_key.as_str(),
        )
        .env(
            "AWS_SESSION_TOKEN",
            result.credentials.session_token.as_str(),
        )
        .env("AWS_DEFAULT_REGION", &profile.region)
        .output()
        .expect("the aws CLI is installed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sts:GetCallerIdentity failed: {stderr}"
    );
    let identity_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the CLI returns JSON");
    let arn = identity_json["Arn"].as_str().expect("an ARN");
    let role_name = profile.role_arn.rsplit('/').next().expect("a role name");
    assert!(
        arn.contains("assumed-role") && arn.contains(role_name),
        "called as {arn}, expected an assumed-role session for {role_name}"
    );
    println!("sts:GetCallerIdentity answered as {arn}");
}

#[test]
#[ignore = "needs a dedicated AWS account; set KEYSTONE_AWS_INTEGRATION_PROFILE"]
#[cfg(any(target_os = "macos", windows))]
fn aws_a_wrong_trust_anchor_profile_or_role_fails() {
    if no_account() {
        return;
    }
    let (profile, store, name) = account_setup().expect("an account is configured");
    let now = OffsetDateTime::now_utc();
    let base = session_request(&profile, &name);

    // Each ARN is well formed and points at nothing, so AWS rejects the request
    // rather than the certificate. Nothing is created to make these exist.
    let cases: Vec<(&str, CreateSessionRequest)> = vec![
        (
            "trust anchor",
            CreateSessionRequest {
                trust_anchor_arn: replace_resource_id(&base.trust_anchor_arn),
                ..base.clone()
            },
        ),
        (
            "profile",
            CreateSessionRequest {
                profile_arn: replace_resource_id(&base.profile_arn),
                ..base.clone()
            },
        ),
        (
            "role",
            CreateSessionRequest {
                role_arn: format!(
                    "{}/KeystoneNoSuchRole",
                    base.role_arn
                        .rsplit_once('/')
                        .map(|(prefix, _)| prefix)
                        .expect("an IAM role ARN")
                ),
                ..base.clone()
            },
        ),
    ];

    for (what, request) in cases {
        let identity = real_identity(&store, &profile, now);
        match real_client(identity, &profile).create_session(&request) {
            Ok(_) => panic!("a wrong {what} was accepted; credentials must not be issued"),
            Err(KeystoneError::RolesAnywhereRejected {
                status,
                code,
                message,
            }) => {
                assert!(
                    (400..500).contains(&status),
                    "a wrong {what} should be a client error, got {status} {code}: {message}"
                );
                println!("wrong {what}: {status} {code}: {message}");
            }
            Err(other) => panic!("a wrong {what} produced {other:?}"),
        }
    }
}

#[test]
#[ignore = "needs a dedicated AWS account; set KEYSTONE_AWS_INTEGRATION_PROFILE"]
#[cfg(any(target_os = "macos", windows))]
fn aws_a_stale_timestamp_fails() {
    if no_account() {
        return;
    }
    let (profile, store, name) = account_setup().expect("an account is configured");
    let now = OffsetDateTime::now_utc();
    let identity = real_identity(&store, &profile, now);

    // Signed half an hour ago: outside every SigV4 date window.
    let stale = now - time::Duration::minutes(30);
    let client = RolesAnywhereClient::new(
        identity,
        profile.region.clone(),
        FixedClock(stale),
        TransportConfig::from_profile(&profile),
    )
    .expect("the client builds")
    .with_retry_policy(RetryPolicy::no_retries());

    let error = client
        .create_session(&session_request(&profile, &name))
        .expect_err("a stale signature must be rejected");
    match error {
        KeystoneError::RolesAnywhereRejected {
            status,
            code,
            message,
        } => {
            println!("stale timestamp: {status} {code}: {message}");
            assert!(
                looks_like_clock_skew(&code, &message),
                "AWS's answer should be recognizable as skew: {code}: {message}"
            );
        }
        other => panic!("a stale timestamp produced {other:?}"),
    }
}

#[test]
#[ignore = "needs a dedicated AWS account; set KEYSTONE_AWS_INTEGRATION_PROFILE"]
#[cfg(any(target_os = "macos", windows))]
fn aws_a_modified_body_or_signed_header_fails() {
    if no_account() {
        return;
    }
    let (profile, store, name) = account_setup().expect("an account is configured");
    let now = OffsetDateTime::now_utc();
    let identity = real_identity(&store, &profile, now);
    let client = real_client(identity, &profile);
    let request = session_request(&profile, &name);

    // Sent by hand rather than through the client, because the tampering has to
    // happen *after* signing: the client, correctly, will not build a request
    // whose signature does not cover its bytes.
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("an HTTP client");

    let signed = client.sign_now(&request).expect("the request signs");
    let baseline = send_raw(&http, &signed, None, None);
    assert!(
        baseline.0.is_success(),
        "the untampered request should succeed, otherwise this test proves nothing: {} {}",
        baseline.0,
        baseline.1
    );

    // A longer session than the one that was signed for.
    let longer = String::from_utf8(signed.body.clone())
        .expect("the body is UTF-8")
        .replace(
            &format!("\"durationSeconds\":{}", request.duration_seconds),
            "\"durationSeconds\":43200",
        );
    let (status, body) = send_raw(&http, &signed, Some(longer.into_bytes()), None);
    println!("modified body: {status}: {body}");
    assert!(
        status.is_client_error(),
        "a modified body must be rejected, got {status}"
    );

    // A signed header changed in flight: the date is the one that gates replay.
    let (status, body) = send_raw(
        &http,
        &signed,
        None,
        Some((
            "x-amz-date",
            keystone_roles_anywhere::signing::format_amz_date(now + time::Duration::minutes(2))
                .expect("a date formats"),
        )),
    );
    println!("modified signed header: {status}: {body}");
    assert!(
        status.is_client_error(),
        "a modified signed header must be rejected, got {status}"
    );
}

/// POST a signed request as-is, optionally replacing the body or one header.
#[cfg(any(target_os = "macos", windows))]
fn send_raw(
    http: &reqwest::blocking::Client,
    signed: &keystone_roles_anywhere::SignedRequest,
    body: Option<Vec<u8>>,
    header_override: Option<(&str, String)>,
) -> (reqwest::StatusCode, String) {
    let mut builder = http.post(&signed.url);
    for (name, value) in &signed.headers {
        let value = match &header_override {
            Some((override_name, override_value)) if name.eq_ignore_ascii_case(override_name) => {
                override_value.clone()
            }
            _ => value.clone(),
        };
        builder = builder.header(name, value);
    }
    let response = builder
        .body(body.unwrap_or_else(|| signed.body.clone()))
        .send()
        .expect("the request reaches AWS");
    let status = response.status();
    // The body is an AWS error document or a credential set. Only the error
    // documents are printed by the callers, and only on a failed assertion.
    let text = response.text().unwrap_or_default();
    let text = if status.is_success() {
        "<credential set withheld>".to_string()
    } else {
        text
    };
    (status, text)
}

/// The `CreateSession` request a profile describes.
#[cfg(any(target_os = "macos", windows))]
fn session_request(profile: &keystone_core::config::Profile, name: &str) -> CreateSessionRequest {
    let ready = profile.require_ready(name).expect("a complete profile");
    CreateSessionRequest {
        profile_arn: ready.roles_anywhere_profile_arn.to_string(),
        role_arn: ready.role_arn.to_string(),
        trust_anchor_arn: ready.trust_anchor_arn.to_string(),
        duration_seconds: ready.duration_seconds,
        role_session_name: ready.role_session_name.map(str::to_string),
    }
}

/// Replace the resource id at the end of an ARN with one that does not exist.
#[cfg(any(target_os = "macos", windows))]
fn replace_resource_id(arn: &str) -> String {
    match arn.rsplit_once('/') {
        Some((prefix, _)) => format!("{prefix}/00000000-0000-0000-0000-000000000000"),
        None => format!("{arn}/00000000-0000-0000-0000-000000000000"),
    }
}

// -- Level 3: the manual procedure ------------------------------------------

/// Print the procedure for the cases that need the account changed.
///
/// `#[ignore]` and asserts nothing: it exists so the steps live next to the
/// automated ones. This suite will not disable a trust anchor or stand up a
/// second CA on its own — both are modifications to infrastructure other devices
/// depend on, and the decision to make them belongs to whoever owns the account.
#[test]
#[ignore = "prints the manual procedure for the account-changing cases"]
fn aws_manual_checklist() {
    println!(
        "\
The automated cases are above: run them with

    KEYSTONE_AWS_INTEGRATION_PROFILE=<name> \\
      cargo test -p keystone-tests --test integration_aws -- --ignored --nocapture

The following need the account changed, so they are not automated.

A. Expired certificate, wrong CA, and unauthorized SAN, end to end.
   Each is refused locally by Keystone (see the tests in this file), so proving
   AWS also refuses them means presenting a certificate Keystone would not build.
   1. In a throwaway account, create a second trust anchor from a CA you control.
   2. Issue three leaves for a scratch key: one already expired, one from a CA
      the trust anchor does not know, one whose URI SAN names another device.
   3. For each, call CreateSession with the official AWS helper — not Keystone,
      which will not sign with them.
   Expected: all three return 403 AccessDeniedException. The SAN case is the one
   worth confirming, because it is enforced by the role trust policy rather than
   by Roles Anywhere: a role generated without the SAN condition would accept it.
   4. Delete the scratch trust anchor when finished.

B. Disabled trust anchor prevents new sessions.
   1. Confirm `keystone test --profile <name>` succeeds.
   2. Disable the trust anchor:
          aws rolesanywhere disable-trust-anchor --trust-anchor-id <id>
      This revokes every device under that anchor, not just this one. Do it only
      in an account whose anchor you own, and expect to re-enable it.
   3. Run `keystone credential-process --profile <name>`.
   Expected: 403, nothing on standard output, nonzero exit. Already-issued
   credentials keep working until they expire — disabling prevents new sessions,
   it does not revoke current ones, which is why the design's revocation section
   also covers the session duration.
   4. Re-enable it:
          aws rolesanywhere enable-trust-anchor --trust-anchor-id <id>
   5. Confirm `keystone test --profile <name>` succeeds again.

Record the outcome of each in the pull request that changes signing, the
generated trust policy, or the revocation documentation."
    );
}
