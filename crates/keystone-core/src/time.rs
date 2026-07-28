//! Time abstractions.
//!
//! AWS request signing is time-sensitive, so Keystone captures one timestamp
//! per signing attempt and uses it consistently. Injecting a clock also lets
//! the golden signing tests pin a timestamp.

use std::sync::Arc;

use time::OffsetDateTime;

use crate::error::{KeystoneError, Result};

/// A source of the current UTC time.
pub trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;
}

/// The real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

/// A clock frozen at one instant, for tests and golden fixtures.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub OffsetDateTime);

impl Clock for FixedClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

/// The default clock, ready to share between components.
pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

/// Earliest time Keystone believes could be "now".
///
/// A Mac with a dead coin cell or a failed time sync can report a date decades
/// off. Signing against such a clock produces a rejection that reads like a
/// certificate problem, so it is worth catching locally with a specific
/// message. This bound only has to be old enough to never reject a real clock;
/// it is the date this check was written.
const PLAUSIBLE_EPOCH: OffsetDateTime = time::macros::datetime!(2026-01-01 0:00 UTC);

/// Reject a local clock that cannot plausibly be correct.
///
/// Only a lower bound is enforced. A clock set far in the future is
/// indistinguishable from a legitimately future date, and AWS will reject the
/// signature with its own skew error, which `keystone doctor` explains.
pub fn check_plausible(now: OffsetDateTime) -> Result<()> {
    if now < PLAUSIBLE_EPOCH {
        return Err(KeystoneError::ClockSkew);
    }
    Ok(())
}

/// Serde support for RFC 3339 timestamps.
///
/// Used for every timestamp Keystone writes, so that config files, identity
/// metadata, and `credential_process` output all agree on one format.
pub mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(
        value: &OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .to_offset(time::UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        let raw = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&raw, &Rfc3339).map_err(serde::de::Error::custom)
    }
}

/// Format a timestamp as UTC RFC 3339, the form used everywhere Keystone prints a time.
pub fn format_rfc3339(value: OffsetDateTime) -> String {
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        // Formatting an OffsetDateTime as RFC 3339 cannot fail for any value
        // representable by the type.
        .unwrap_or_else(|_| value.to_string())
}

/// Parse a UTC RFC 3339 timestamp.
pub fn parse_rfc3339(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).map_err(|e| {
        KeystoneError::InvalidConfiguration(format!("invalid timestamp {value:?}: {e}"))
    })
}

/// Render a duration the way Keystone reports certificate lifetimes.
pub fn describe_duration_days(duration: time::Duration) -> String {
    let days = duration.whole_days();
    match days {
        d if d < 0 => "in the past".to_string(),
        0 => "today".to_string(),
        1 => "1 day".to_string(),
        d => format!("{d} days"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plausible_clock_is_accepted() {
        assert!(check_plausible(time::macros::datetime!(2026-07-25 12:00 UTC)).is_ok());
    }

    #[test]
    fn a_clock_before_the_plausible_epoch_is_reported_as_skew() {
        let stale = time::macros::datetime!(2001-01-01 0:00 UTC);
        assert!(matches!(
            check_plausible(stale),
            Err(KeystoneError::ClockSkew)
        ));
    }

    #[test]
    fn a_future_clock_is_left_for_aws_to_reject() {
        // Keystone cannot tell a fast clock from a future date, so it does not guess.
        assert!(check_plausible(time::macros::datetime!(2126-01-01 0:00 UTC)).is_ok());
    }

    #[test]
    fn timestamps_round_trip_through_rfc3339() {
        let value = time::macros::datetime!(2026-07-26 01:15:00 UTC);
        assert_eq!(format_rfc3339(value), "2026-07-26T01:15:00Z");
        assert_eq!(parse_rfc3339("2026-07-26T01:15:00Z").unwrap(), value);
    }

    #[test]
    fn non_utc_timestamps_are_normalized_to_utc_when_formatted() {
        let value = time::macros::datetime!(2026-07-26 03:15:00 +2);
        assert_eq!(format_rfc3339(value), "2026-07-26T01:15:00Z");
    }

    #[test]
    fn fixed_clocks_do_not_advance() {
        let instant = time::macros::datetime!(2026-07-26 01:15:00 UTC);
        let clock = FixedClock(instant);
        assert_eq!(clock.now_utc(), instant);
        assert_eq!(clock.now_utc(), instant);
    }

    #[test]
    fn durations_are_described_in_whole_days() {
        assert_eq!(describe_duration_days(time::Duration::days(90)), "90 days");
        assert_eq!(describe_duration_days(time::Duration::days(1)), "1 day");
        assert_eq!(describe_duration_days(time::Duration::hours(5)), "today");
        assert_eq!(
            describe_duration_days(time::Duration::days(-3)),
            "in the past"
        );
    }
}
