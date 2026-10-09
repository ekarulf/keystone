//! End-to-end `CreateSession` tests against a stub server.
//!
//! A software P-256 key and a test certificate exchanged for temporary
//! credentials, exercising the real signing, transport, response parsing, and
//! retry code paths. The hardware-backed counterpart lives in each platform
//! crate's own `create_session` test, which drives this same stub server.

use std::time::Duration;

use keystone_core::error::KeystoneError;
use keystone_core::time::FixedClock;
use keystone_roles_anywhere::testing::stub_server::{StubResponse, StubServer};
use keystone_roles_anywhere::testing::TestIdentity;
use keystone_roles_anywhere::{
    CreateSessionRequest, RetryPolicy, RolesAnywhereClient, TransportConfig,
};

const NOW: time::OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

/// A clock that advances by a fixed step on every reading, so a retry observes
/// a later time than the attempt before it.
struct AdvancingClock {
    start: time::OffsetDateTime,
    step: time::Duration,
    readings: std::sync::atomic::AtomicU32,
}

impl AdvancingClock {
    fn new(start: time::OffsetDateTime, step: time::Duration) -> Self {
        Self {
            start,
            step,
            readings: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl keystone_core::time::Clock for AdvancingClock {
    fn now_utc(&self) -> time::OffsetDateTime {
        let taken = self
            .readings
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.start + self.step * i32::try_from(taken).unwrap_or(i32::MAX)
    }
}

const SUCCESS_BODY: &str = r#"{
  "credentialSet": [
    {
      "assumedRoleUser": {
        "arn": "arn:aws:sts::123456789012:assumed-role/ExampleDeviceRole/example-laptop"
      },
      "credentials": {
        "accessKeyId": "ASIAEXAMPLE",
        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "sessionToken": "IQoJb3JpZ2luX2VjEXAMPLETOKEN",
        "expiration": "2026-07-26T02:15:00Z"
      }
    }
  ]
}"#;

fn request() -> CreateSessionRequest {
    CreateSessionRequest {
        profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/p".to_string(),
        role_arn: "arn:aws:iam::123456789012:role/ExampleDeviceRole".to_string(),
        trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/t".to_string(),
        duration_seconds: 3600,
        role_session_name: Some("example-laptop".to_string()),
    }
}

fn client(server: &StubServer) -> RolesAnywhereClient<TestIdentity, FixedClock> {
    RolesAnywhereClient::new(
        TestIdentity::new(),
        "us-east-1",
        FixedClock(NOW),
        TransportConfig {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
        },
    )
    .expect("client builds")
    .with_endpoint_override(server.base_url())
    // Tests assert the retry schedule, not the wall-clock wait.
    .with_sleeper(|_| {})
}

#[test]
fn a_signed_request_is_exchanged_for_temporary_credentials() {
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&server)
        .create_session(&request())
        .expect("credentials issued");

    assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");
    assert_eq!(
        *result.credentials.secret_access_key,
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    );
    assert_eq!(
        result.credentials.expiration,
        time::macros::datetime!(2026-07-26 02:15:00 UTC)
    );
    assert_eq!(
        result.assumed_role_arn.as_deref(),
        Some("arn:aws:sts::123456789012:assumed-role/ExampleDeviceRole/example-laptop")
    );
    assert!(result.credentials.validate(NOW).is_ok());
}

#[test]
fn the_request_on_the_wire_matches_what_aws_expects() {
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    client(&server)
        .create_session(&request())
        .expect("credentials issued");

    let captured = server.requests();
    assert_eq!(captured.len(), 1);
    let sent = &captured[0];

    assert_eq!(sent.method, "POST");
    assert_eq!(sent.path, "/sessions");
    assert_eq!(sent.header("content-type"), Some("application/json"));
    assert_eq!(sent.header("x-amz-date"), Some("20260726T011500Z"));
    assert!(sent.header("x-amz-x509").is_some());

    let authorization = sent.header("authorization").expect("authorization header");
    assert!(authorization.starts_with("AWS4-X509-ECDSA-SHA256 Credential="));
    assert!(authorization.contains("/20260726/us-east-1/rolesanywhere/aws4_request"));
    assert!(authorization.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-x509"));

    let body = sent.body_json();
    assert_eq!(body["durationSeconds"], 3600);
    assert_eq!(body["roleSessionName"], "example-laptop");
    assert_eq!(
        body["roleArn"],
        "arn:aws:iam::123456789012:role/ExampleDeviceRole"
    );
}

#[test]
fn the_signature_sent_verifies_over_the_body_sent() {
    // The end-to-end version of the unit-level check: recompute the
    // string-to-sign from the bytes the server received and verify the
    // signature from the header against it.
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let identity = TestIdentity::new();

    // Borrowed, so the test keeps the identity to verify with afterwards.
    RolesAnywhereClient::new(
        &identity,
        "us-east-1",
        FixedClock(NOW),
        TransportConfig::default(),
    )
    .expect("client builds")
    .with_endpoint_override(server.base_url())
    .create_session(&request())
    .expect("credentials issued");

    let sent = server.requests().remove(0);
    let signature_hex = sent
        .header("authorization")
        .and_then(|value| value.split("Signature=").nth(1))
        .expect("signature present");

    // Rebuild the string-to-sign from the wire bytes alone.
    let mut headers = keystone_roles_anywhere::signing::SignedHeaders::new();
    for name in ["content-type", "host", "x-amz-date", "x-amz-x509"] {
        headers.insert(name, sent.header(name).expect(name));
    }
    let canonical = keystone_roles_anywhere::signing::canonical_request(&headers, &sent.body);
    let string_to_sign = keystone_roles_anywhere::signing::string_to_sign(
        keystone_roles_anywhere::signing::ALGORITHM_ECDSA_SHA256,
        NOW,
        "us-east-1",
        &canonical,
    )
    .expect("string to sign");

    assert!(
        identity.verify(
            string_to_sign.as_bytes(),
            &hex::decode(signature_hex).expect("hex signature")
        ),
        "signature does not verify over the request as received"
    );
}

#[test]
fn the_host_header_names_the_aws_endpoint_not_the_stub() {
    // The signature covers `host`, so the override must not change it.
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    client(&server)
        .create_session(&request())
        .expect("credentials issued");
    assert_eq!(
        server.requests()[0].header("host"),
        Some("rolesanywhere.us-east-1.amazonaws.com")
    );
}

#[test]
fn an_access_denied_response_is_reported_without_retrying() {
    let server = StubServer::start(vec![StubResponse::error(
        403,
        r#"{"message":"not authorized to perform rolesanywhere:CreateSession","__type":"AccessDeniedException"}"#,
    )
    .with_header("x-amzn-RequestId", "req-abc123")]);

    let error = client(&server)
        .create_session(&request())
        .expect_err("should be rejected");

    match error {
        KeystoneError::RolesAnywhereRejected {
            status,
            code,
            message,
        } => {
            assert_eq!(status, 403);
            assert_eq!(code, "AccessDeniedException");
            assert!(message.contains("not authorized"), "{message}");
            assert!(message.contains("req-abc123"), "{message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    // A permissions failure will fail identically on a second try.
    assert_eq!(server.request_count(), 1);
}

#[test]
fn a_throttled_request_is_retried_and_can_then_succeed() {
    let server = StubServer::start(vec![
        StubResponse::error(
            429,
            r#"{"message":"slow down","__type":"TooManyRequestsException"}"#,
        ),
        StubResponse::ok(SUCCESS_BODY),
    ]);

    let result = client(&server)
        .create_session(&request())
        .expect("second attempt succeeds");
    assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");
    assert_eq!(server.request_count(), 2);
}

#[test]
fn each_retry_is_signed_again_with_the_current_time() {
    // AWS rejects a stale `x-amz-date`, so replaying the first attempt's
    // signature after a backoff would turn a transient failure into a signature
    // error. The clock advances a minute per reading to make that visible.
    let server = StubServer::start(vec![
        StubResponse::error(503, "{}"),
        StubResponse::ok(SUCCESS_BODY),
    ]);
    let identity = TestIdentity::new();
    RolesAnywhereClient::new(
        &identity,
        "us-east-1",
        AdvancingClock::new(NOW, time::Duration::minutes(1)),
        TransportConfig::default(),
    )
    .expect("client builds")
    .with_endpoint_override(server.base_url())
    .with_sleeper(|_| {})
    .create_session(&request())
    .expect("second attempt succeeds");

    let captured = server.requests();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].header("x-amz-date"), Some("20260726T011500Z"));
    assert_eq!(captured[1].header("x-amz-date"), Some("20260726T011600Z"));
    // A new date means a new string-to-sign, so the signature must differ too.
    assert_ne!(
        captured[0].header("authorization"),
        captured[1].header("authorization")
    );
    assert!(captured[1]
        .header("authorization")
        .expect("authorization")
        .contains("/20260726/us-east-1/rolesanywhere/aws4_request"));
}

#[test]
fn persistent_server_errors_exhaust_the_attempt_limit_and_stop() {
    let server = StubServer::start(vec![StubResponse::error(500, "{}")]);
    let error = client(&server)
        .create_session(&request())
        .expect_err("should give up");
    assert!(matches!(
        error,
        KeystoneError::RolesAnywhereRejected { status: 500, .. }
    ));
    assert_eq!(
        server.request_count(),
        RetryPolicy::default().max_attempts as usize
    );
}

#[test]
fn attempts_are_recorded_for_diagnostics() {
    let server = StubServer::start(vec![
        StubResponse::error(503, r#"{"message":"unavailable"}"#),
        StubResponse::ok(SUCCESS_BODY),
    ]);
    let mut attempts = Vec::new();
    client(&server)
        .create_session_recording(&request(), &mut attempts)
        .expect("second attempt succeeds");

    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].status, Some(503));
    assert!(attempts[0].error.is_some());
    assert_eq!(attempts[1].status, Some(200));
    assert!(attempts[1].error.is_none());
}

#[test]
fn a_malformed_success_body_is_not_retried() {
    // The response arrived intact; retrying would only produce the same
    // unparseable body.
    let server = StubServer::start(vec![StubResponse::ok(r#"{"credentialSet":[]}"#)]);
    let error = client(&server)
        .create_session(&request())
        .expect_err("should be rejected");
    assert!(matches!(error, KeystoneError::InvalidCredentialResponse(_)));
    assert_eq!(server.request_count(), 1);
}

#[test]
fn a_redirect_is_not_followed() {
    // Following one would send the signed authorization header and the device
    // certificate to a host the signature was not computed for.
    let server = StubServer::start(vec![StubResponse {
        status: 302,
        body: String::new(),
        headers: vec![(
            "Location".to_string(),
            "http://127.0.0.1:1/sessions".to_string(),
        )],
    }]);
    let error = client(&server)
        .create_session(&request())
        .expect_err("should not follow the redirect");
    assert!(
        matches!(
            error,
            KeystoneError::RolesAnywhereRejected { status: 302, .. }
        ),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 1);
}

#[test]
fn the_no_retry_policy_makes_exactly_one_attempt() {
    let server = StubServer::start(vec![StubResponse::error(503, "{}")]);
    let error = client(&server)
        .with_retry_policy(RetryPolicy::no_retries())
        .create_session(&request())
        .expect_err("should not retry");
    assert!(matches!(
        error,
        KeystoneError::RolesAnywhereRejected { status: 503, .. }
    ));
    assert_eq!(server.request_count(), 1);
}

#[test]
fn credentials_are_never_written_to_a_debug_rendering() {
    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&server)
        .create_session(&request())
        .expect("credentials issued");

    let rendered = format!("{result:?}");
    assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
    assert!(!rendered.contains("IQoJb3JpZ2luX2Vj"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}
