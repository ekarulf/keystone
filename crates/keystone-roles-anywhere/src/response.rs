//! Parsing the `CreateSession` response.

use keystone_core::credentials::AwsSessionCredentials;
use keystone_core::error::{KeystoneError, Result};
use serde::Deserialize;
use zeroize::Zeroizing;

/// The `CreateSession` success payload.
///
/// AWS returns a list of credential sets, one per subject, but a Keystone
/// request names exactly one role, so exactly one entry is expected.
#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    #[serde(default, rename = "credentialSet")]
    credential_set: Vec<CredentialSetEntry>,
}

#[derive(Debug, Deserialize)]
struct CredentialSetEntry {
    credentials: Option<ResponseCredentials>,
    #[serde(rename = "assumedRoleUser")]
    assumed_role_user: Option<AssumedRoleUser>,
}

#[derive(Debug, Deserialize)]
struct ResponseCredentials {
    #[serde(rename = "accessKeyId")]
    access_key_id: Option<String>,
    #[serde(rename = "secretAccessKey")]
    secret_access_key: Option<String>,
    #[serde(rename = "sessionToken")]
    session_token: Option<String>,
    expiration: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AssumedRoleUser {
    arn: Option<String>,
}

/// A parsed `CreateSession` result.
pub struct SessionResult {
    pub credentials: AwsSessionCredentials,
    /// The assumed-role ARN, when AWS reports it. Used to confirm the session
    /// belongs to the role that was requested.
    pub assumed_role_arn: Option<String>,
}

impl std::fmt::Debug for SessionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionResult")
            .field("credentials", &self.credentials)
            .field("assumed_role_arn", &self.assumed_role_arn)
            .finish()
    }
}

/// Parse a successful `CreateSession` body.
pub fn parse_session_response(body: &[u8]) -> Result<SessionResult> {
    let response: CreateSessionResponse = serde_json::from_slice(body).map_err(|e| {
        KeystoneError::InvalidCredentialResponse(format!("response is not valid JSON: {e}"))
    })?;

    let entry = match response.credential_set.len() {
        1 => &response.credential_set[0],
        0 => {
            return Err(KeystoneError::InvalidCredentialResponse(
                "response contained no credentials".to_string(),
            ))
        }
        // More than one set means the profile mapped the request to several
        // roles; picking one arbitrarily could hand back the wrong privileges.
        n => {
            return Err(KeystoneError::InvalidCredentialResponse(format!(
                "response contained {n} credential sets; expected exactly one"
            )))
        }
    };

    let credentials = entry.credentials.as_ref().ok_or_else(|| {
        KeystoneError::InvalidCredentialResponse("credential set has no credentials".to_string())
    })?;

    let missing = |field: &str| {
        KeystoneError::InvalidCredentialResponse(format!("response is missing {field}"))
    };

    let expiration_raw = credentials
        .expiration
        .as_deref()
        .ok_or_else(|| missing("expiration"))?;
    let expiration = keystone_core::time::parse_rfc3339(expiration_raw).map_err(|_| {
        KeystoneError::InvalidCredentialResponse(format!(
            "expiration {expiration_raw:?} is not a valid RFC 3339 timestamp"
        ))
    })?;

    Ok(SessionResult {
        credentials: AwsSessionCredentials {
            access_key_id: credentials
                .access_key_id
                .clone()
                .ok_or_else(|| missing("accessKeyId"))?,
            secret_access_key: Zeroizing::new(
                credentials
                    .secret_access_key
                    .clone()
                    .ok_or_else(|| missing("secretAccessKey"))?,
            ),
            session_token: Zeroizing::new(
                credentials
                    .session_token
                    .clone()
                    .ok_or_else(|| missing("sessionToken"))?,
            ),
            expiration,
        },
        assumed_role_arn: entry
            .assumed_role_user
            .as_ref()
            .and_then(|user| user.arn.clone()),
    })
}

/// An AWS error payload.
#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(alias = "Message", alias = "message")]
    message: Option<String>,
    #[serde(alias = "__type", alias = "code", alias = "Code")]
    code: Option<String>,
}

/// Turn a non-2xx response into a Keystone error.
///
/// The AWS error code is preserved because it is the most useful thing to
/// search for, and the message often names the specific ARN or certificate
/// field at fault.
pub fn parse_error_response(status: u16, body: &[u8], request_id: Option<&str>) -> KeystoneError {
    let parsed: Option<ErrorBody> = serde_json::from_slice(body).ok();
    let code = parsed
        .as_ref()
        .and_then(|e| e.code.clone())
        .map(|code| {
            // AWS sometimes qualifies the type as `com.amazonaws...#AccessDenied`.
            code.rsplit('#').next().unwrap_or(&code).to_string()
        })
        .unwrap_or_else(|| default_code_for_status(status).to_string());

    let mut message = parsed
        .as_ref()
        .and_then(|e| e.message.clone())
        .unwrap_or_else(|| {
            let text = String::from_utf8_lossy(body).trim().to_string();
            if text.is_empty() {
                "no error message returned".to_string()
            } else {
                text
            }
        });
    if let Some(request_id) = request_id {
        message.push_str(&format!(" (request id {request_id})"));
    }

    KeystoneError::RolesAnywhereRejected {
        status,
        code,
        message,
    }
}

fn default_code_for_status(status: u16) -> &'static str {
    match status {
        400 => "ValidationException",
        403 => "AccessDeniedException",
        404 => "ResourceNotFoundException",
        429 => "TooManyRequestsException",
        500..=599 => "ServiceError",
        _ => "UnknownError",
    }
}

/// Whether an AWS rejection looks like local clock skew.
///
/// Any signature complaint counts, which is broader than it first appears it
/// should be. Signing 30 minutes off the correct time against a real trust
/// anchor returns exactly:
///
/// ```text
/// 403 AccessDeniedException: Invalid signature
/// ```
///
/// There is no "expired", no date, no mention of a clock — so a narrower rule
/// that looked for that wording reported a skewed clock as an unexplained
/// signature failure. The costly confusion this exists to prevent is between a
/// clock problem and a certificate or permissions problem, and those are worded
/// unmistakably differently ("Specified Trust Anchor wasn't found", "Invalid or
/// empty profile provided", "Requested Role isn't one of those listed in the
/// Profile"), none of which mention a signature. A tampered request is also
/// reported as an invalid signature, but Keystone signs every attempt itself, so
/// in normal operation the clock is the explanation that remains.
pub fn looks_like_clock_skew(code: &str, message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    code.contains("Signature")
        || message.contains("signature")
        || message.contains("too skewed")
        || message.contains("clock")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUCCESS: &str = r#"{
      "credentialSet": [
        {
          "assumedRoleUser": {
            "arn": "arn:aws:sts::123456789012:assumed-role/KeystonePersonalMac/example-laptop",
            "assumedRoleId": "AROAEXAMPLE:example-laptop"
          },
          "credentials": {
            "accessKeyId": "ASIAEXAMPLE",
            "secretAccessKey": "secret-value",
            "sessionToken": "token-value",
            "expiration": "2026-07-26T01:15:00Z"
          },
          "packedPolicySize": 0,
          "roleArn": "arn:aws:iam::123456789012:role/KeystonePersonalMac",
          "sourceIdentity": "example-laptop"
        }
      ],
      "subjectArn": "arn:aws:rolesanywhere:us-east-1:123456789012:subject/abc"
    }"#;

    #[test]
    fn a_successful_response_yields_credentials_and_the_assumed_role() {
        let result = parse_session_response(SUCCESS.as_bytes()).unwrap();
        assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");
        assert_eq!(*result.credentials.secret_access_key, "secret-value");
        assert_eq!(*result.credentials.session_token, "token-value");
        assert_eq!(
            result.credentials.expiration,
            time::macros::datetime!(2026-07-26 01:15:00 UTC)
        );
        assert!(result
            .assumed_role_arn
            .unwrap()
            .contains("assumed-role/KeystonePersonalMac"));
    }

    #[test]
    fn a_response_with_no_credentials_is_rejected() {
        let error = parse_session_response(br#"{"credentialSet":[]}"#).unwrap_err();
        assert!(matches!(error, KeystoneError::InvalidCredentialResponse(_)));
    }

    #[test]
    fn a_response_with_several_credential_sets_is_rejected() {
        // Choosing one arbitrarily could return the wrong role's privileges.
        let body = SUCCESS.replace("\"subjectArn\"", "\"ignored\": 0, \"subjectArn\"");
        let doubled = body.replace(
            "\"credentialSet\": [",
            "\"credentialSet\": [{\"credentials\":{\"accessKeyId\":\"A\",\"secretAccessKey\":\"B\",\"sessionToken\":\"C\",\"expiration\":\"2026-07-26T01:15:00Z\"}},",
        );
        let error = parse_session_response(doubled.as_bytes()).unwrap_err();
        assert!(
            error.to_string().contains("expected exactly one"),
            "{error}"
        );
    }

    #[test]
    fn a_response_missing_a_credential_field_names_the_field() {
        let body = SUCCESS.replace("\"sessionToken\": \"token-value\",", "");
        let error = parse_session_response(body.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("sessionToken"), "{error}");
    }

    #[test]
    fn a_malformed_expiration_is_rejected() {
        let body = SUCCESS.replace("2026-07-26T01:15:00Z", "not-a-timestamp");
        let error = parse_session_response(body.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("RFC 3339"), "{error}");
    }

    #[test]
    fn non_json_is_rejected_rather_than_panicking() {
        assert!(parse_session_response(b"<html>gateway timeout</html>").is_err());
        assert!(parse_session_response(b"").is_err());
    }

    #[test]
    fn an_aws_error_body_is_reported_with_its_code_and_message() {
        let body = br#"{"message":"No profile found","__type":"ResourceNotFoundException"}"#;
        let error = parse_error_response(404, body, Some("req-123"));
        match error {
            KeystoneError::RolesAnywhereRejected {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 404);
                assert_eq!(code, "ResourceNotFoundException");
                assert!(message.contains("No profile found"));
                assert!(message.contains("req-123"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn a_qualified_error_type_is_reduced_to_the_code() {
        let body =
            br#"{"message":"nope","__type":"com.amazonaws.rolesanywhere#AccessDeniedException"}"#;
        match parse_error_response(403, body, None) {
            KeystoneError::RolesAnywhereRejected { code, .. } => {
                assert_eq!(code, "AccessDeniedException");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn an_unparseable_error_body_still_produces_a_useful_error() {
        match parse_error_response(503, b"<html>Service Unavailable</html>", None) {
            KeystoneError::RolesAnywhereRejected {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 503);
                assert_eq!(code, "ServiceError");
                assert!(message.contains("Service Unavailable"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn an_empty_error_body_does_not_produce_an_empty_message() {
        match parse_error_response(500, b"", None) {
            KeystoneError::RolesAnywhereRejected { message, .. } => {
                assert!(!message.is_empty());
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn signature_failures_are_recognized_as_possible_clock_skew() {
        assert!(looks_like_clock_skew(
            "InvalidSignatureException",
            "The request signature we calculated does not match"
        ));
        assert!(looks_like_clock_skew(
            "ValidationException",
            "Signature expired: 20260726T011500Z is now earlier than the allowed date"
        ));
        assert!(looks_like_clock_skew(
            "ValidationException",
            "clock skew detected"
        ));
    }

    #[test]
    fn the_wording_real_aws_uses_for_a_stale_signature_is_recognized() {
        // Verbatim from IAM Roles Anywhere for a request signed 30 minutes off
        // the correct time. It names neither the clock nor a date, so a rule that
        // required that wording missed the case this function exists for.
        assert!(looks_like_clock_skew(
            "AccessDeniedException",
            "Invalid signature"
        ));
    }

    #[test]
    fn unrelated_failures_are_not_attributed_to_the_clock() {
        assert!(!looks_like_clock_skew(
            "ResourceNotFoundException",
            "Profile not found"
        ));
        assert!(!looks_like_clock_skew(
            "AccessDeniedException",
            "not authorized to perform rolesanywhere:CreateSession"
        ));
    }

    #[test]
    fn the_wording_real_aws_uses_for_setup_mistakes_is_not_attributed_to_the_clock() {
        // Also verbatim, from pointing a real signed request at a trust anchor,
        // profile, and role it is not entitled to. These are the failures that
        // must not be misreported as a clock problem, and none names a signature.
        for message in [
            "Specified Trust Anchor wasn't found.",
            "Invalid or empty profile provided.",
            "Requested Role isn't one of those listed in the Profile.",
        ] {
            assert!(
                !looks_like_clock_skew("AccessDeniedException", message),
                "{message} is a setup mistake, not clock skew"
            );
        }
    }
}
