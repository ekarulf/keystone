//! Shared plumbing for the commands: where files live, what time it is, and
//! where output goes.
//!
//! One rule shapes the output helpers: `keystone credential-process` writes
//! credential JSON to standard output and *nothing else*. Every diagnostic in
//! every command therefore goes through [`Context::note`], which writes to
//! standard error, so no command can accidentally interleave a progress message
//! into the credential stream.

use std::io::Write as _;
use std::path::PathBuf;

use keystone_core::config::{Config, Paths, Profile};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use keystone_core::store::Store;
use keystone_core::time::{Clock, SystemClock};
use time::OffsetDateTime;

/// Everything a command needs that is not one of its own arguments.
pub struct Context {
    pub store: Store,
    pub clock: Box<dyn Clock>,
    pub verbose: bool,
}

impl Context {
    pub fn new(
        home: Option<PathBuf>,
        allow_unsafe_permissions: bool,
        verbose: bool,
    ) -> Result<Self> {
        let paths = match home {
            Some(root) => Paths::rooted_at(root),
            None => Paths::discover()?,
        };
        Ok(Self {
            store: Store::new(paths).allow_unsafe_permissions(allow_unsafe_permissions),
            clock: Box::new(SystemClock),
            verbose,
        })
    }

    pub fn now(&self) -> OffsetDateTime {
        self.clock.now_utc()
    }

    /// The current time, refusing to proceed if the clock is obviously wrong.
    ///
    /// AWS rejects a signature more than a few minutes out of date, and the
    /// resulting error names the signature rather than the clock. Checking here
    /// turns that into a message the user can act on.
    pub fn now_checked(&self) -> Result<OffsetDateTime> {
        let now = self.now();
        keystone_core::time::check_plausible(now)?;
        Ok(now)
    }

    /// Write a diagnostic line to standard error.
    pub fn note(&self, message: impl std::fmt::Display) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{message}");
    }

    /// Write a diagnostic line only under `--verbose`.
    pub fn detail(&self, message: impl std::fmt::Display) {
        if self.verbose {
            self.note(message);
        }
    }

    pub fn load_config(&self) -> Result<Config> {
        self.store.load_config()
    }

    /// Load one profile, or fail naming it.
    pub fn load_profile(&self, name: &str) -> Result<Profile> {
        Ok(self.load_config()?.profile(name)?.clone())
    }

    /// The key id recorded for a profile, or an error naming the command that
    /// creates one.
    pub fn require_key_id(&self, name: &str, profile: &Profile) -> Result<KeyId> {
        profile
            .key_id
            .clone()
            .ok_or_else(|| KeystoneError::ProfileIncomplete {
                profile: name.to_string(),
                reason: format!(
                    "no {} identity yet. Run `keystone bootstrap --profile <name>` (or \
                     `keystone init` to enroll with your own CA).",
                    crate::backend::KEY_STORE
                ),
            })
    }

    /// Save a modified configuration.
    pub fn save_config(&self, config: &Config) -> Result<()> {
        self.store.save_config(config)
    }
}

/// Write a line to standard output, failing if the stream is closed.
///
/// A closed stdout matters: `keystone credential-process | head` would otherwise
/// exit zero having emitted nothing, and the SDK would report a confusing empty
/// credential response rather than a failure.
pub fn print_line(text: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")
        .and_then(|()| stdout.flush())
        .map_err(|error| KeystoneError::io("cannot write to standard output", error))
}

/// Parse a validity duration like `5y`, `18m`, `90d`, or a bare number of days.
///
/// Years and months are approximated in days, which is what a certificate
/// validity window needs; the exact end date is derived from the start time.
pub fn parse_validity(input: &str) -> Result<time::Duration> {
    let trimmed = input.trim();
    let invalid = || {
        KeystoneError::InvalidConfiguration(format!(
            "{input:?} is not a validity period. Use a number of days, or a suffix: 90d, 18m, 5y."
        ))
    };
    if trimmed.is_empty() {
        return Err(invalid());
    }

    let (digits, days_per_unit) = match trimmed.chars().last().expect("non-empty") {
        'y' | 'Y' => (&trimmed[..trimmed.len() - 1], 365),
        'm' | 'M' => (&trimmed[..trimmed.len() - 1], 30),
        'd' | 'D' => (&trimmed[..trimmed.len() - 1], 1),
        _ => (trimmed, 1),
    };

    let count: i64 = digits.parse().map_err(|_| invalid())?;
    if count <= 0 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{input:?} is not a positive validity period"
        )));
    }
    let days = count.checked_mul(days_per_unit).ok_or_else(invalid)?;
    // A certificate valid for a century is a mistake, not a preference.
    if days > 365 * 30 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{input:?} is longer than 30 years; a device certificate should not outlive the device"
        )));
    }
    Ok(time::Duration::days(days))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validity_periods_parse_in_the_forms_the_design_uses() {
        assert_eq!(parse_validity("5y").unwrap(), time::Duration::days(365 * 5));
        assert_eq!(parse_validity("10y").unwrap(), time::Duration::days(3650));
        assert_eq!(parse_validity("18m").unwrap(), time::Duration::days(540));
        assert_eq!(parse_validity("90d").unwrap(), time::Duration::days(90));
        assert_eq!(parse_validity("90").unwrap(), time::Duration::days(90));
        assert_eq!(parse_validity(" 5y ").unwrap(), time::Duration::days(1825));
    }

    #[test]
    fn a_meaningless_validity_period_is_refused_with_the_accepted_forms() {
        for input in ["", "y", "-1y", "0d", "abc", "5 years", "1000y"] {
            let error = parse_validity(input).unwrap_err();
            assert!(
                matches!(error, KeystoneError::InvalidConfiguration(_)),
                "{input:?} produced {error}"
            );
        }
        assert!(format!("{}", parse_validity("abc").unwrap_err()).contains("90d"));
    }
}
