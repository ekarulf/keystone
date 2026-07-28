//! Retry policy for `CreateSession`.
//!
//! Keystone runs inside `credential_process`, which means a caller — often an
//! interactive `aws` command — is blocked while it retries. The policy is
//! therefore deliberately small: a few attempts, short bounded waits, and no
//! retries at all for failures that cannot succeed on a second try.

use std::time::Duration;

use keystone_core::error::KeystoneError;

/// How many total attempts a single `CreateSession` call makes.
pub const MAX_ATTEMPTS: u32 = 3;

/// The wait before the second attempt; each further attempt doubles it.
pub const BASE_BACKOFF: Duration = Duration::from_millis(200);

/// The ceiling on any single wait, so a slow retry cannot look like a hang.
pub const MAX_BACKOFF: Duration = Duration::from_secs(2);

/// The retry policy, parameterized so tests can assert the schedule without
/// waiting for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_ATTEMPTS,
            base_backoff: BASE_BACKOFF,
            max_backoff: MAX_BACKOFF,
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries, for `doctor` and other diagnostics that
    /// should report the first failure verbatim.
    pub fn no_retries() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    /// Whether another attempt should be made after `error` on `attempt`.
    ///
    /// `attempt` is 1-based, so the last attempt never schedules a retry no
    /// matter how retryable the error looks.
    pub fn should_retry(&self, attempt: u32, error: &KeystoneError) -> bool {
        attempt < self.max_attempts && error.is_retryable()
    }

    /// The wait before the attempt following `attempt`.
    ///
    /// Full jitter — a uniform draw from `[0, backoff]` — rather than a fixed
    /// delay, so several shells starting at once do not retry in lockstep.
    /// `jitter` is a caller-supplied value in `[0, 1]`.
    pub fn backoff(&self, attempt: u32, jitter: f64) -> Duration {
        let jitter = jitter.clamp(0.0, 1.0);
        let exponent = attempt.saturating_sub(1).min(16);
        let scaled = self
            .base_backoff
            .saturating_mul(1u32 << exponent)
            .min(self.max_backoff);
        scaled.mul_f64(jitter)
    }
}

/// A jitter value in `[0, 1)` derived from the current time.
///
/// Sub-millisecond wall-clock noise is enough to spread out retries; a full
/// random-number generator would be a dependency with nothing else to do here.
pub fn wall_clock_jitter() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    f64::from(nanos % 1_000_000) / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_failures_are_retried_until_the_attempt_limit() {
        let policy = RetryPolicy::default();
        let error = KeystoneError::Network("connection reset".to_string());
        assert!(policy.should_retry(1, &error));
        assert!(policy.should_retry(2, &error));
        // The third attempt is the last one.
        assert!(!policy.should_retry(3, &error));
    }

    #[test]
    fn throttling_and_server_faults_are_retried() {
        let policy = RetryPolicy::default();
        for status in [429, 500, 502, 503, 504] {
            let error = KeystoneError::RolesAnywhereRejected {
                status,
                code: "ServiceError".to_string(),
                message: String::new(),
            };
            assert!(policy.should_retry(1, &error), "status {status}");
        }
    }

    #[test]
    fn client_errors_are_never_retried() {
        // Retrying an AccessDenied or a bad ARN only delays the real message.
        let policy = RetryPolicy::default();
        for status in [400, 403, 404] {
            let error = KeystoneError::RolesAnywhereRejected {
                status,
                code: "ValidationException".to_string(),
                message: String::new(),
            };
            assert!(!policy.should_retry(1, &error), "status {status}");
        }
    }

    #[test]
    fn certificate_and_clock_failures_are_never_retried() {
        let policy = RetryPolicy::default();
        for error in [
            KeystoneError::ClockSkew,
            KeystoneError::CertificateKeyMismatch,
            KeystoneError::SecureEnclaveUnavailable,
            KeystoneError::InvalidCredentialResponse("bad".to_string()),
        ] {
            assert!(!policy.should_retry(1, &error), "{error}");
        }
    }

    #[test]
    fn the_no_retry_policy_makes_a_single_attempt() {
        let policy = RetryPolicy::no_retries();
        let error = KeystoneError::Network("timeout".to_string());
        assert!(!policy.should_retry(1, &error));
    }

    #[test]
    fn backoff_doubles_per_attempt() {
        let policy = RetryPolicy::default();
        // Full jitter of 1.0 gives the upper bound of each window.
        assert_eq!(policy.backoff(1, 1.0), Duration::from_millis(200));
        assert_eq!(policy.backoff(2, 1.0), Duration::from_millis(400));
        assert_eq!(policy.backoff(3, 1.0), Duration::from_millis(800));
    }

    #[test]
    fn backoff_is_capped_so_a_retry_cannot_look_like_a_hang() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.backoff(20, 1.0), MAX_BACKOFF);
    }

    #[test]
    fn jitter_scales_the_wait_down_but_never_up() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.backoff(1, 0.0), Duration::ZERO);
        assert_eq!(policy.backoff(1, 0.5), Duration::from_millis(100));
        // Out-of-range jitter is clamped rather than trusted.
        assert_eq!(policy.backoff(1, 9.0), Duration::from_millis(200));
        assert_eq!(policy.backoff(1, -1.0), Duration::ZERO);
    }

    #[test]
    fn the_total_wait_of_a_full_retry_sequence_stays_interactive() {
        let policy = RetryPolicy::default();
        let total: Duration = (1..policy.max_attempts)
            .map(|attempt| policy.backoff(attempt, 1.0))
            .sum();
        assert!(total < Duration::from_secs(1), "{total:?}");
    }

    #[test]
    fn wall_clock_jitter_is_a_fraction() {
        let jitter = wall_clock_jitter();
        assert!((0.0..1.0).contains(&jitter), "{jitter}");
    }
}
