//! The `CreateSession` HTTP transport.

use std::time::Duration;

use keystone_core::error::{KeystoneError, Result};
use keystone_core::time::Clock;
use reqwest::blocking::Client;

use crate::request::{
    AwsX509Identity, CreateSessionRequest, RolesAnywhereRequestSigner, SignedRequest,
};
use crate::response::{parse_error_response, parse_session_response, SessionResult};
use crate::retry::{wall_clock_jitter, RetryPolicy};

/// Transport settings for a `CreateSession` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(20),
        }
    }
}

impl TransportConfig {
    /// Build settings from a profile's configured timeouts.
    pub fn from_profile(profile: &keystone_core::config::Profile) -> Self {
        Self {
            connect_timeout: Duration::from_secs(u64::from(profile.connect_timeout_seconds)),
            request_timeout: Duration::from_secs(u64::from(profile.request_timeout_seconds)),
        }
    }
}

/// Build the HTTP client used for `CreateSession`.
///
/// Redirects are disabled: a redirect would carry the signed `Authorization`
/// header and the device certificate to a host the signature was not computed
/// for. Timeouts are always set, because a `credential_process` that never
/// returns hangs whatever invoked it with no diagnostic.
pub fn build_client(config: TransportConfig) -> Result<Client> {
    Client::builder()
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        // rustls negotiates TLS 1.2+ only; stated explicitly so a future
        // default cannot quietly relax it.
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .user_agent(concat!("keystone/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| KeystoneError::Network(format!("cannot build HTTP client: {e}")))
}

/// What one `CreateSession` attempt produced, for diagnostics.
#[derive(Debug)]
pub struct AttemptRecord {
    pub attempt: u32,
    pub status: Option<u16>,
    pub request_id: Option<String>,
    /// The failure, if the attempt did not succeed.
    pub error: Option<String>,
}

/// A `CreateSession` client bound to one identity and region.
pub struct RolesAnywhereClient<I, C> {
    signer: RolesAnywhereRequestSigner<I>,
    http: Client,
    clock: C,
    retry: RetryPolicy,
    /// Where to sleep between attempts. Injected so tests do not wait.
    sleeper: fn(Duration),
    /// Substitute base URL, available only to tests. Production always derives
    /// the endpoint from the region, so no configuration or environment
    /// variable can redirect a signed request and its certificate elsewhere.
    #[cfg(any(test, feature = "testing"))]
    endpoint_override: Option<String>,
}

fn thread_sleep(duration: Duration) {
    std::thread::sleep(duration);
}

impl<I: AwsX509Identity, C: Clock> RolesAnywhereClient<I, C> {
    pub fn new(
        identity: I,
        region: impl Into<String>,
        clock: C,
        config: TransportConfig,
    ) -> Result<Self> {
        Ok(Self {
            signer: RolesAnywhereRequestSigner::new(identity, region),
            http: build_client(config)?,
            clock,
            retry: RetryPolicy::default(),
            sleeper: thread_sleep,
            #[cfg(any(test, feature = "testing"))]
            endpoint_override: None,
        })
    }

    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Replace the sleep function, so tests can assert the retry schedule
    /// without spending the wall-clock time.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_sleeper(mut self, sleeper: fn(Duration)) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Send requests to a stub server instead of AWS.
    ///
    /// The request is still signed for the real regional host, so the stub sees
    /// exactly the bytes AWS would.
    #[cfg(any(test, feature = "testing"))]
    pub fn with_endpoint_override(mut self, base_url: impl Into<String>) -> Self {
        self.endpoint_override = Some(base_url.into());
        self
    }

    pub fn signer(&self) -> &RolesAnywhereRequestSigner<I> {
        &self.signer
    }

    /// Sign a request at the current time, without sending it.
    ///
    /// Used by `keystone test --debug-signing` and the golden tests.
    pub fn sign_now(&self, request: &CreateSessionRequest) -> Result<SignedRequest> {
        self.signer.sign(request, self.clock.now_utc())
    }

    /// Exchange the device identity for temporary credentials.
    ///
    /// Every attempt is signed afresh: AWS rejects a stale `x-amz-date`, so
    /// reusing the first attempt's signature after a backoff would turn a
    /// transient network failure into a signature error.
    pub fn create_session(&self, request: &CreateSessionRequest) -> Result<SessionResult> {
        self.create_session_recording(request, &mut Vec::new())
    }

    /// As `create_session`, additionally recording one entry per attempt.
    pub fn create_session_recording(
        &self,
        request: &CreateSessionRequest,
        attempts: &mut Vec<AttemptRecord>,
    ) -> Result<SessionResult> {
        let mut attempt = 1;
        loop {
            let signed = self.signer.sign(request, self.clock.now_utc())?;
            let outcome = self.send_once(&signed);

            let error = match outcome {
                Ok((status, request_id, body)) => {
                    if (200..300).contains(&status) {
                        attempts.push(AttemptRecord {
                            attempt,
                            status: Some(status),
                            request_id,
                            error: None,
                        });
                        return parse_session_response(&body);
                    }
                    let error = parse_error_response(status, &body, request_id.as_deref());
                    attempts.push(AttemptRecord {
                        attempt,
                        status: Some(status),
                        request_id,
                        error: Some(error.to_string()),
                    });
                    error
                }
                Err(error) => {
                    attempts.push(AttemptRecord {
                        attempt,
                        status: None,
                        request_id: None,
                        error: Some(error.to_string()),
                    });
                    error
                }
            };

            if !self.retry.should_retry(attempt, &error) {
                return Err(error);
            }
            (self.sleeper)(self.retry.backoff(attempt, wall_clock_jitter()));
            attempt += 1;
        }
    }

    /// Send one signed request, returning the status, request id, and body.
    ///
    /// A transport failure is a `Network` error; an HTTP status is returned as
    /// data, because whether it is retryable is the retry policy's decision.
    fn send_once(&self, signed: &SignedRequest) -> Result<(u16, Option<String>, Vec<u8>)> {
        let mut builder = self.http.post(self.destination(signed));
        for (name, value) in &signed.headers {
            builder = builder.header(name, value);
        }
        let response = builder
            .body(signed.body.clone())
            .send()
            .map_err(describe_transport_error)?;

        let status = response.status().as_u16();
        let request_id = ["x-amzn-requestid", "x-amzn-RequestId", "x-amz-request-id"]
            .iter()
            .find_map(|name| response.headers().get(*name))
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response
            .bytes()
            .map_err(|e| KeystoneError::Network(format!("cannot read response body: {e}")))?
            .to_vec();
        Ok((status, request_id, body))
    }

    /// The URL to POST to: always the signed URL outside tests.
    fn destination(&self, signed: &SignedRequest) -> String {
        #[cfg(any(test, feature = "testing"))]
        if let Some(base) = &self.endpoint_override {
            return format!(
                "{}{}",
                base.trim_end_matches('/'),
                crate::signing::CREATE_SESSION_PATH
            );
        }
        signed.url.clone()
    }
}

/// Turn a reqwest failure into a message that names the likely cause.
///
/// The default `reqwest` display is a nest of source errors; a
/// `credential_process` caller usually only shows the top line, so the useful
/// distinction — offline, DNS, TLS, or timeout — has to be in that line.
fn describe_transport_error(error: reqwest::Error) -> KeystoneError {
    let detail = if error.is_timeout() {
        "request timed out".to_string()
    } else if error.is_connect() {
        "cannot connect to the IAM Roles Anywhere endpoint (check network and DNS)".to_string()
    } else if error.is_redirect() {
        // Redirects are disabled; reaching here means AWS tried to redirect a
        // signed request, which must not be followed.
        "endpoint attempted a redirect, which Keystone does not follow".to_string()
    } else {
        error.to_string()
    };
    KeystoneError::Network(format!("{detail}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::time::FixedClock;

    use crate::testing::TestIdentity;

    const NOW: time::OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn request() -> CreateSessionRequest {
        CreateSessionRequest {
            profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/p".to_string(),
            role_arn: "arn:aws:iam::123456789012:role/KeystonePersonalMac".to_string(),
            trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/t"
                .to_string(),
            duration_seconds: 3600,
            role_session_name: Some("erik-macbook".to_string()),
        }
    }

    fn client() -> RolesAnywhereClient<TestIdentity, FixedClock> {
        RolesAnywhereClient::new(
            TestIdentity::new(),
            "us-east-1",
            FixedClock(NOW),
            TransportConfig::default(),
        )
        .unwrap()
    }

    #[test]
    fn the_client_builds_with_bounded_timeouts() {
        build_client(TransportConfig::default()).unwrap();
    }

    #[test]
    fn transport_settings_come_from_the_profile() {
        let mut profile = keystone_core::config::Profile::new("us-east-1");
        profile.connect_timeout_seconds = 3;
        profile.request_timeout_seconds = 11;
        let config = TransportConfig::from_profile(&profile);
        assert_eq!(config.connect_timeout, Duration::from_secs(3));
        assert_eq!(config.request_timeout, Duration::from_secs(11));
    }

    #[test]
    fn signing_uses_the_injected_clock() {
        let signed = client().sign_now(&request()).unwrap();
        assert!(signed
            .headers
            .iter()
            .any(|(name, value)| name == "x-amz-date" && value == "20260726T011500Z"));
    }

    #[test]
    fn a_request_that_cannot_be_sent_is_reported_as_a_network_failure() {
        // Port 1 on the loopback interface refuses connections, which exercises
        // the transport error path without a live AWS endpoint. The signer is
        // pointed at a real region, so only the send fails.
        let client = RolesAnywhereClient::new(
            TestIdentity::new(),
            "us-east-1",
            FixedClock(NOW),
            TransportConfig {
                connect_timeout: Duration::from_millis(50),
                request_timeout: Duration::from_millis(200),
            },
        )
        .unwrap()
        .with_retry_policy(RetryPolicy::no_retries())
        .with_sleeper(|_| {});

        let mut signed = client.sign_now(&request()).unwrap();
        signed.url = "http://127.0.0.1:1/sessions".to_string();
        let error = client.send_once(&signed).unwrap_err();
        assert!(matches!(error, KeystoneError::Network(_)), "{error:?}");
    }

    #[test]
    fn every_attempt_is_signed_with_a_fresh_signature() {
        // Two signings of the same request must both verify; a cached signature
        // would go stale against AWS's date window.
        let identity = TestIdentity::new();
        let client = RolesAnywhereClient::new(
            &identity,
            "us-east-1",
            FixedClock(NOW),
            TransportConfig::default(),
        )
        .unwrap();
        let first = client.sign_now(&request()).unwrap();
        let second = client.sign_now(&request()).unwrap();
        assert_eq!(first.string_to_sign, second.string_to_sign);
        for signed in [&first, &second] {
            let signature = signed
                .headers
                .iter()
                .find(|(name, _)| name == "authorization")
                .and_then(|(_, v)| v.split("Signature=").nth(1))
                .unwrap();
            assert!(identity.verify(
                signed.string_to_sign.as_bytes(),
                &hex::decode(signature).unwrap()
            ));
        }
    }
}
