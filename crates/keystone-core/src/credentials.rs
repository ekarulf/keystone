//! Temporary AWS credentials and the `credential_process` contract.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::error::{KeystoneError, Result};
use crate::time::{format_rfc3339, rfc3339};

/// Temporary AWS credentials returned by IAM Roles Anywhere.
///
/// The secret fields are wrapped in `Zeroizing` and the `Debug` implementation
/// is written by hand, so that a stray `{:?}` in a log statement cannot leak
/// them. `Clone` is deliberately not derived: copies are extra places a secret
/// can outlive its use.
pub struct AwsSessionCredentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Zeroizing<String>,
    pub expiration: OffsetDateTime,
}

impl std::fmt::Debug for AwsSessionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsSessionCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .field("expiration", &self.expiration)
            .finish()
    }
}

impl AwsSessionCredentials {
    /// Check a credential set is usable before handing it to the AWS SDK.
    ///
    /// An expired or partially populated response would otherwise surface much
    /// later as an opaque AWS authentication failure in the calling tool.
    pub fn validate(&self, now: OffsetDateTime) -> Result<()> {
        if self.access_key_id.is_empty() {
            return Err(KeystoneError::InvalidCredentialResponse(
                "access key id is empty".to_string(),
            ));
        }
        if self.secret_access_key.is_empty() {
            return Err(KeystoneError::InvalidCredentialResponse(
                "secret access key is empty".to_string(),
            ));
        }
        if self.session_token.is_empty() {
            return Err(KeystoneError::InvalidCredentialResponse(
                "session token is empty".to_string(),
            ));
        }
        if self.expiration <= now {
            return Err(KeystoneError::InvalidCredentialResponse(format!(
                "credentials already expired at {}",
                format_rfc3339(self.expiration)
            )));
        }
        Ok(())
    }

    /// Whether these credentials should be refreshed rather than reused.
    pub fn needs_refresh(&self, now: OffsetDateTime, refresh_before: time::Duration) -> bool {
        now >= self.expiration - refresh_before
    }

    /// Convert to the JSON shape the AWS `credential_process` contract expects.
    pub fn to_process_output(&self) -> CredentialProcessOutput {
        CredentialProcessOutput {
            version: CREDENTIAL_PROCESS_VERSION,
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.to_string(),
            session_token: self.session_token.to_string(),
            expiration: format_rfc3339(self.expiration),
        }
    }
}

/// The version field of the AWS process credential-provider contract.
pub const CREDENTIAL_PROCESS_VERSION: u8 = 1;

/// The JSON document written to standard output by `keystone credential-process`.
///
/// Holds the same secrets as [`AwsSessionCredentials`], and protects them the same
/// way: a hand-written `Debug` and a `Drop` that zeroizes, matching
/// [`CachedCredentials`] below. The fields stay plain `String`s because `serde`
/// must see the types it can serialize — `Zeroizing` implements neither
/// `Serialize` nor `Deserialize` — so the wiping happens on drop instead.
///
/// Worth the trouble even though this type is short-lived: it is the one place a
/// secret exists as a plain `String` on its way to standard output, so a future
/// `{:?}` here would print credentials into a diagnostic.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessOutput {
    pub version: u8,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

impl Drop for CredentialProcessOutput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

impl std::fmt::Debug for CredentialProcessOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialProcessOutput")
            .field("version", &self.version)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .field("expiration", &self.expiration)
            .finish()
    }
}

/// A cached credential set, as stored under the cache directory.
///
/// Same secrets and same protections as [`CredentialProcessOutput`]: a
/// hand-written `Debug` and a zeroizing `Drop`, with the fields left as plain
/// `String`s for `serde`'s sake.
#[derive(Serialize, Deserialize)]
pub struct CachedCredentials {
    pub version: u8,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    #[serde(with = "rfc3339")]
    pub expiration: OffsetDateTime,
    /// Which profile these belong to, so a mismatched cache file is ignored
    /// rather than serving credentials for the wrong role.
    pub profile: String,
    /// The role these credentials were issued for, checked on read for the same reason.
    pub role_arn: String,
}

/// The current cache-file schema version.
pub const CACHE_VERSION: u8 = 1;

impl CachedCredentials {
    pub fn new(credentials: &AwsSessionCredentials, profile: &str, role_arn: &str) -> Self {
        Self {
            version: CACHE_VERSION,
            access_key_id: credentials.access_key_id.clone(),
            secret_access_key: credentials.secret_access_key.to_string(),
            session_token: credentials.session_token.to_string(),
            expiration: credentials.expiration,
            profile: profile.to_string(),
            role_arn: role_arn.to_string(),
        }
    }

    /// Interpret a cache entry, rejecting one that does not belong to this request.
    pub fn to_credentials(&self, profile: &str, role_arn: &str) -> Result<AwsSessionCredentials> {
        if self.version != CACHE_VERSION {
            return Err(KeystoneError::InvalidCredentialResponse(format!(
                "cached credentials have unsupported version {}",
                self.version
            )));
        }
        if self.profile != profile || self.role_arn != role_arn {
            return Err(KeystoneError::InvalidCredentialResponse(
                "cached credentials belong to a different profile or role".to_string(),
            ));
        }
        Ok(AwsSessionCredentials {
            access_key_id: self.access_key_id.clone(),
            secret_access_key: Zeroizing::new(self.secret_access_key.clone()),
            session_token: Zeroizing::new(self.session_token.clone()),
            expiration: self.expiration,
        })
    }
}

impl Drop for CachedCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

impl std::fmt::Debug for CachedCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedCredentials")
            .field("version", &self.version)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field("session_token", &"<redacted>")
            .field("expiration", &self.expiration)
            .field("profile", &self.profile)
            .field("role_arn", &self.role_arn)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(expiration: OffsetDateTime) -> AwsSessionCredentials {
        AwsSessionCredentials {
            access_key_id: "ASIAEXAMPLE".to_string(),
            secret_access_key: Zeroizing::new("secret-value".to_string()),
            session_token: Zeroizing::new("token-value".to_string()),
            expiration,
        }
    }

    const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 00:00:00 UTC);

    #[test]
    fn valid_credentials_pass_validation() {
        let creds = credentials(NOW + time::Duration::hours(1));
        creds.validate(NOW).unwrap();
    }

    #[test]
    fn expired_credentials_are_rejected() {
        let creds = credentials(NOW - time::Duration::seconds(1));
        assert!(matches!(
            creds.validate(NOW),
            Err(KeystoneError::InvalidCredentialResponse(_))
        ));
    }

    #[test]
    fn credentials_expiring_exactly_now_are_rejected() {
        let creds = credentials(NOW);
        assert!(creds.validate(NOW).is_err());
    }

    #[test]
    fn empty_credential_fields_are_rejected() {
        let mut creds = credentials(NOW + time::Duration::hours(1));
        creds.access_key_id = String::new();
        assert!(creds.validate(NOW).is_err());

        let mut creds = credentials(NOW + time::Duration::hours(1));
        creds.secret_access_key = Zeroizing::new(String::new());
        assert!(creds.validate(NOW).is_err());

        let mut creds = credentials(NOW + time::Duration::hours(1));
        creds.session_token = Zeroizing::new(String::new());
        assert!(creds.validate(NOW).is_err());
    }

    #[test]
    fn refresh_is_due_inside_the_refresh_window() {
        let creds = credentials(NOW + time::Duration::minutes(4));
        assert!(creds.needs_refresh(NOW, time::Duration::minutes(5)));
    }

    #[test]
    fn refresh_is_not_due_outside_the_refresh_window() {
        let creds = credentials(NOW + time::Duration::minutes(30));
        assert!(!creds.needs_refresh(NOW, time::Duration::minutes(5)));
    }

    #[test]
    fn debug_output_never_contains_secret_material() {
        // All three credential-carrying types, because each has its own
        // hand-written `Debug` and any one of them reverting to a derive would
        // reintroduce the leak.
        let creds = credentials(NOW + time::Duration::hours(1));
        let rendered = vec![
            format!("{creds:?}"),
            format!("{:?}", creds.to_process_output()),
            format!(
                "{:?}",
                CachedCredentials::new(&creds, "personal", "arn:aws:iam::1:role/R")
            ),
        ];
        for rendered in rendered {
            assert!(!rendered.contains("secret-value"), "{rendered}");
            assert!(!rendered.contains("token-value"), "{rendered}");
            // The access key id is not secret and is useful when diagnosing.
            assert!(rendered.contains("ASIAEXAMPLE"), "{rendered}");
        }
    }

    #[test]
    fn process_output_uses_the_pascal_case_contract() {
        let creds = credentials(time::macros::datetime!(2026-07-26 01:15:00 UTC));
        let json = serde_json::to_string(&creds.to_process_output()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["Version"], 1);
        assert_eq!(parsed["AccessKeyId"], "ASIAEXAMPLE");
        assert_eq!(parsed["SecretAccessKey"], "secret-value");
        assert_eq!(parsed["SessionToken"], "token-value");
        assert_eq!(parsed["Expiration"], "2026-07-26T01:15:00Z");
    }

    #[test]
    fn cached_credentials_round_trip_for_the_same_profile_and_role() {
        let creds = credentials(NOW + time::Duration::hours(1));
        let cached = CachedCredentials::new(&creds, "personal", "arn:aws:iam::1:role/R");
        let restored = cached
            .to_credentials("personal", "arn:aws:iam::1:role/R")
            .unwrap();
        assert_eq!(restored.access_key_id, creds.access_key_id);
        assert_eq!(*restored.secret_access_key, *creds.secret_access_key);
        assert_eq!(restored.expiration, creds.expiration);
    }

    #[test]
    fn cached_credentials_for_another_profile_or_role_are_refused() {
        let creds = credentials(NOW + time::Duration::hours(1));
        let cached = CachedCredentials::new(&creds, "personal", "arn:aws:iam::1:role/R");
        assert!(cached
            .to_credentials("work", "arn:aws:iam::1:role/R")
            .is_err());
        assert!(cached
            .to_credentials("personal", "arn:aws:iam::1:role/Other")
            .is_err());
    }

    #[test]
    fn cached_credentials_with_an_unknown_version_are_refused() {
        let creds = credentials(NOW + time::Duration::hours(1));
        let mut cached = CachedCredentials::new(&creds, "personal", "arn:aws:iam::1:role/R");
        cached.version = CACHE_VERSION + 1;
        assert!(cached
            .to_credentials("personal", "arn:aws:iam::1:role/R")
            .is_err());
    }
}
