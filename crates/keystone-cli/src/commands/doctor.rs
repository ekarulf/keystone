//! `keystone doctor` — run every check and report what is wrong.
//!
//! The design's list, in order: key-store availability, key restoration,
//! unattended signing, configuration and credential-cache permissions,
//! certificate parsing,
//! certificate validity, certificate/key match, CA chain validation, URI SAN
//! presence, endpoint reachability, local clock, Roles Anywhere authentication,
//! AWS shared-config integration, certificate expiration, trust-anchor
//! configuration.
//!
//! Unlike every other command, `doctor` does not stop at the first failure: a
//! machine with an expired certificate *and* a bad clock should learn both in one
//! run. So each check returns an [`Outcome`] instead of propagating, and the
//! command's exit status is derived from the collected results at the end.

use keystone_core::config::Profile;
use keystone_core::error::{KeystoneError, Result};
use keystone_core::signer::KeystoneSigningIdentity as _;
use keystone_pki::ParsedCertificate;

use crate::cli::ProfileArgs;
use crate::context::{print_line, Context};
use crate::exchange::{self, DebugSigning};
use crate::identity::LoadedIdentity;

/// What one check concluded.
enum Outcome {
    Pass(String),
    /// Something to act on eventually, which does not stop Keystone working.
    Warn(String),
    Fail(String),
    /// Not attempted, because an earlier check makes it meaningless.
    Skip(String),
}

impl Outcome {
    fn marker(&self) -> &'static str {
        match self {
            Self::Pass(_) => "ok  ",
            Self::Warn(_) => "warn",
            Self::Fail(_) => "FAIL",
            Self::Skip(_) => "skip",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Pass(m) | Self::Warn(m) | Self::Fail(m) | Self::Skip(m) => m,
        }
    }
}

struct Report {
    checks: Vec<(&'static str, Outcome)>,
}

impl Report {
    fn new() -> Self {
        Self { checks: Vec::new() }
    }

    fn add(&mut self, name: &'static str, outcome: Outcome) -> &Outcome {
        self.checks.push((name, outcome));
        &self.checks.last().expect("just pushed").1
    }

    /// Record `Pass` with `detail`, or `Fail` with the error.
    fn check(&mut self, name: &'static str, detail: impl Into<String>, result: Result<()>) -> bool {
        match result {
            Ok(()) => {
                self.add(name, Outcome::Pass(detail.into()));
                true
            }
            Err(error) => {
                self.add(name, Outcome::Fail(error.to_string()));
                false
            }
        }
    }

    fn failures(&self) -> usize {
        self.checks
            .iter()
            .filter(|(_, outcome)| matches!(outcome, Outcome::Fail(_)))
            .count()
    }

    fn warnings(&self) -> usize {
        self.checks
            .iter()
            .filter(|(_, outcome)| matches!(outcome, Outcome::Warn(_)))
            .count()
    }

    /// Checks that were not attempted.
    ///
    /// Counted separately so the summary cannot report them as passes. A run with
    /// no certificate installed skips five checks; calling those "passed" would tell
    /// a user their certificate is fine when Keystone never looked at one.
    fn skips(&self) -> usize {
        self.checks
            .iter()
            .filter(|(_, outcome)| matches!(outcome, Outcome::Skip(_)))
            .count()
    }

    fn passes(&self) -> usize {
        self.checks
            .iter()
            .filter(|(_, outcome)| matches!(outcome, Outcome::Pass(_)))
            .count()
    }
}

pub fn run(context: &Context, args: &ProfileArgs) -> Result<()> {
    let mut report = Report::new();

    // The clock first: every later check that involves a validity window or a
    // signature depends on it, so a wrong clock explains their failures.
    let now = match context.now_checked() {
        Ok(now) => {
            report.add(
                "local clock",
                Outcome::Pass(keystone_core::time::format_rfc3339(now)),
            );
            Some(now)
        }
        Err(error) => {
            report.add("local clock", Outcome::Fail(error.to_string()));
            None
        }
    };

    // Named for whichever key store this build uses, so a Windows user sees "TPM"
    // rather than a macOS term they cannot act on.
    let key_store = crate::backend::report();
    report.add(
        crate::backend::KEY_STORE,
        if key_store.available {
            Outcome::Pass("available".to_string())
        } else {
            Outcome::Fail(
                key_store
                    .detail
                    .clone()
                    .unwrap_or_else(|| "unavailable".to_string()),
            )
        },
    );

    check_permissions(context, &mut report, &args.profile);

    let profile = match context.load_profile(&args.profile) {
        Ok(profile) => {
            report.add(
                "profile",
                Outcome::Pass(format!("{} in region {}", args.profile, profile.region)),
            );
            Some(profile)
        }
        Err(error) => {
            report.add("profile", Outcome::Fail(error.to_string()));
            None
        }
    };

    if let (Some(profile), Some(now)) = (&profile, now) {
        let loaded = check_identity(context, &mut report, &args.profile, profile, now);
        check_trust_anchor(&mut report, &args.profile, profile);
        check_endpoint(&mut report, profile);
        check_shared_config(&mut report, &args.profile);
        check_authentication(
            context,
            &mut report,
            &args.profile,
            profile,
            loaded.as_ref(),
            now,
        );
    } else {
        for name in [
            "key restoration",
            "unattended signing",
            "certificate",
            "certificate/key match",
            "CA chain",
            "device URI SAN",
            "certificate expiration",
            "trust-anchor configuration",
            "endpoint",
            "AWS shared config",
            "Roles Anywhere authentication",
        ] {
            report.add(
                name,
                Outcome::Skip("no usable profile or clock".to_string()),
            );
        }
    }

    for (name, outcome) in &report.checks {
        print_line(&format!(
            "[{}] {name}: {}",
            outcome.marker(),
            outcome.message()
        ))?;
    }
    print_line("")?;

    let failures = report.failures();
    let warnings = report.warnings();
    let skips = report.skips();
    if failures == 0 {
        // Passes are counted, not derived by subtraction: a skip is not a pass, and
        // reporting "15 check(s) passed" for a run that never looked at a
        // certificate is the kind of false reassurance `doctor` exists to prevent.
        let not_run = if skips > 0 {
            format!(", {skips} not run")
        } else {
            String::new()
        };
        print_line(&format!(
            "{} check(s) passed, {warnings} warning(s){not_run}.",
            report.passes()
        ))?;
        return Ok(());
    }

    print_line(&format!("{failures} check(s) failed."))?;
    Err(KeystoneError::Other(format!(
        "keystone doctor found {failures} problem(s) with profile {:?}",
        args.profile
    )))
}

/// Report on the files whose write permissions Keystone relies on.
///
/// Deliberately calls [`keystone_core::config::check_not_group_or_world_writable`]
/// directly rather than `Store::check_trusted`, so `--allow-unsafe-permissions`
/// cannot silence it. Every other command has to decide whether to *act* on a
/// file, which the override is for; `doctor` only reports, and a user who asked
/// for the override still needs to be told what it is overriding.
fn check_permissions(context: &Context, report: &mut Report, profile_name: &str) {
    // The cache is listed second but is the more sensitive of the two: it holds a
    // live secret access key and session token, whereas a tampered config would
    // still have to get past certificate pairing.
    for (name, path) in [
        (
            "configuration permissions",
            context.store.paths().config_file(),
        ),
        (
            "credential cache permissions",
            context.store.paths().credential_cache_file(profile_name),
        ),
    ] {
        if path.exists() {
            report.check(
                name,
                format!("{} is not writable by other users", path.display()),
                keystone_core::config::check_not_group_or_world_writable(&path),
            );
        } else {
            report.add(
                name,
                Outcome::Skip(format!("{} does not exist yet", path.display())),
            );
        }
    }
}

/// Key restoration, unattended signing, and every certificate check.
fn check_identity(
    context: &Context,
    report: &mut Report,
    profile_name: &str,
    profile: &Profile,
    now: time::OffsetDateTime,
) -> Option<LoadedIdentity> {
    let key = match crate::identity::load_key(&context.store, profile_name, profile) {
        Ok(key) => {
            report.add(
                "key restoration",
                Outcome::Pass(format!(
                    "restored {} ({})",
                    key.key_id(),
                    profile.key_accessibility.describe()
                )),
            );
            Some(key)
        }
        Err(error) => {
            report.add("key restoration", Outcome::Fail(error.to_string()));
            None
        }
    };

    if let Some(key) = &key {
        // "Unattended" is the property that matters: this signs without a prompt,
        // so a Touch ID or Windows Hello dialog would appear here rather than
        // during an automated credential refresh.
        report.check(
            "unattended signing",
            "signed a probe with no user interaction",
            key.self_test(),
        );
    } else {
        report.add(
            "unattended signing",
            Outcome::Skip("the key did not restore".to_string()),
        );
    }

    let Some(fingerprint) = &profile.certificate_fingerprint_sha256 else {
        for name in [
            "certificate",
            "certificate/key match",
            "CA chain",
            "device URI SAN",
            "certificate expiration",
        ] {
            report.add(
                name,
                Outcome::Fail(
                    "no certificate is installed; run `keystone bootstrap` or `keystone enroll \
                     install`"
                        .to_string(),
                ),
            );
        }
        return None;
    };

    let pair = context
        .store
        .load_certificates(fingerprint)
        .and_then(|(leaf, ca)| {
            Ok((
                ParsedCertificate::from_der(&leaf)?,
                ParsedCertificate::from_der(&ca)?,
            ))
        });
    let (leaf, ca) = match pair {
        Ok(pair) => {
            report.add(
                "certificate",
                Outcome::Pass(format!(
                    "{} (serial {})",
                    pair.0.subject, pair.0.serial_decimal
                )),
            );
            pair
        }
        Err(error) => {
            report.add("certificate", Outcome::Fail(error.to_string()));
            for name in [
                "certificate/key match",
                "CA chain",
                "device URI SAN",
                "certificate expiration",
            ] {
                report.add(
                    name,
                    Outcome::Skip("the certificate is unreadable".to_string()),
                );
            }
            return None;
        }
    };

    report.check(
        "CA chain",
        format!("chains to {}", ca.subject),
        keystone_pki::validate_chain(&leaf, &[], &ca, now),
    );

    match leaf.device_key_id() {
        Some(key_id) if profile.key_id.as_ref() == Some(&key_id) => {
            report.add("device URI SAN", Outcome::Pass(key_id.device_san_uri()));
        }
        Some(key_id) => {
            report.add(
                "device URI SAN",
                Outcome::Fail(format!(
                    "the certificate names {} but the profile records {}",
                    key_id.device_san_uri(),
                    profile
                        .key_id
                        .as_ref()
                        .map(|k| k.device_san_uri())
                        .unwrap_or_else(|| "no key".to_string())
                )),
            );
        }
        None => {
            report.add(
                "device URI SAN",
                Outcome::Fail("the certificate has no urn:keystone:device: URI SAN".to_string()),
            );
        }
    }

    match keystone_pki::validate::expiry_warning(&leaf, now, time::Duration::days(90)) {
        None => {
            report.add(
                "certificate expiration",
                Outcome::Pass(format!(
                    "{} remaining",
                    keystone_core::time::describe_duration_days(leaf.remaining(now))
                )),
            );
        }
        Some(message) => {
            let renewable = profile.issuer.as_ref().is_some_and(|i| i.renewable);
            let message = if renewable {
                message
            } else {
                format!(
                    "{message}. It was issued by a destroyed ephemeral CA and cannot be renewed; \
                     run `keystone rotate --profile {profile_name}`"
                )
            };
            // Expired is a failure; merely approaching expiry is a warning.
            if leaf.remaining(now).is_negative() {
                report.add("certificate expiration", Outcome::Fail(message));
            } else {
                report.add("certificate expiration", Outcome::Warn(message));
            }
        }
    }

    // Pairing runs the full device-certificate validation, including the
    // public-key comparison, so this is the certificate/key match check.
    let loaded = crate::identity::load_identity(&context.store, profile_name, profile, now);
    match &loaded {
        Ok(loaded) => {
            report.check(
                "certificate/key match",
                "the hardware key signs verifiably under this certificate",
                loaded
                    .identity
                    .verify_signing_path(b"keystone doctor signing probe"),
            );
        }
        Err(error) => {
            report.add("certificate/key match", Outcome::Fail(error.to_string()));
        }
    }
    loaded.ok()
}

fn check_trust_anchor(report: &mut Report, profile_name: &str, profile: &Profile) {
    match profile.require_ready(profile_name) {
        Ok(_) => {
            report.add(
                "trust-anchor configuration",
                Outcome::Pass(profile.trust_anchor_arn.clone()),
            );
        }
        Err(_) => {
            // Phrased here rather than reusing `require_ready`'s message, which is
            // written for a caller that was about to sign. The command must be
            // copy-pastable: `sync-profile` requires `--outputs`, and printing it
            // without one hands the user a command that fails.
            report.add(
                "trust-anchor configuration",
                Outcome::Fail(format!(
                    "the profile is missing an ARN. Deploy the generated stack, then run \
                     `keystone infra cdk sync-profile --profile {profile_name} --outputs \
                     ./keystone-infra/cdk-outputs.json`."
                )),
            );
        }
    }
}

/// Confirm the regional endpoint resolves and accepts a TLS connection.
///
/// Deliberately not a `CreateSession`: this separates "the network is broken"
/// from "AWS rejected the identity", which the authentication check reports.
fn check_endpoint(report: &mut Report, profile: &Profile) {
    let endpoint = match keystone_roles_anywhere::endpoint_for_region(&profile.region) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            report.add("endpoint", Outcome::Fail(error.to_string()));
            return;
        }
    };

    let client = match keystone_roles_anywhere::client::build_client(
        keystone_roles_anywhere::TransportConfig::from_profile(profile),
    ) {
        Ok(client) => client,
        Err(error) => {
            report.add("endpoint", Outcome::Fail(error.to_string()));
            return;
        }
    };

    // An unsigned GET: any HTTP response at all proves DNS, TCP, and TLS work.
    // A 403 or 404 is a pass, because it came from the service.
    match client.get(&endpoint).send() {
        Ok(response) => {
            report.add(
                "endpoint",
                Outcome::Pass(format!(
                    "{endpoint} responded {}",
                    response.status().as_u16()
                )),
            );
        }
        Err(error) => {
            report.add(
                "endpoint",
                Outcome::Fail(format!("cannot reach {endpoint}: {error}")),
            );
        }
    }
}

/// Look for a shared-config profile wired to this Keystone profile.
///
/// A warning, never a failure: the user may configure the SDK by environment
/// variable, or from a config file elsewhere.
fn check_shared_config(report: &mut Report, profile_name: &str) {
    let path = match std::env::var_os("AWS_CONFIG_FILE") {
        Some(value) => std::path::PathBuf::from(value),
        None => match std::env::var_os("HOME") {
            Some(home) => std::path::PathBuf::from(home).join(".aws").join("config"),
            None => {
                report.add(
                    "AWS shared config",
                    Outcome::Skip("no HOME, so ~/.aws/config cannot be located".to_string()),
                );
                return;
            }
        },
    };

    let Ok(text) = std::fs::read_to_string(&path) else {
        report.add(
            "AWS shared config",
            Outcome::Warn(format!(
                "{} does not exist. Add a profile with:\n         credential_process = keystone \
                 credential-process --profile {profile_name}",
                path.display()
            )),
        );
        return;
    };

    // A textual search, not an INI parse: this only has to answer "did the user
    // wire this up", and a false negative costs a warning.
    let wired = text.lines().any(|line| {
        line.contains("credential_process")
            && line.contains("keystone")
            && line.contains(profile_name)
    });
    if wired {
        report.add(
            "AWS shared config",
            Outcome::Pass(format!(
                "{} runs keystone credential-process for {profile_name}",
                path.display()
            )),
        );
    } else {
        report.add(
            "AWS shared config",
            Outcome::Warn(format!(
                "{} has no credential_process entry for profile {profile_name}",
                path.display()
            )),
        );
    }
}

fn check_authentication(
    context: &Context,
    report: &mut Report,
    profile_name: &str,
    profile: &Profile,
    loaded: Option<&LoadedIdentity>,
    now: time::OffsetDateTime,
) {
    let Some(loaded) = loaded else {
        report.add(
            "Roles Anywhere authentication",
            Outcome::Skip("the local identity is not usable".to_string()),
        );
        return;
    };

    let request = match exchange::session_request(profile_name, profile) {
        Ok(request) => request,
        Err(error) => {
            report.add(
                "Roles Anywhere authentication",
                Outcome::Fail(error.to_string()),
            );
            return;
        }
    };

    match exchange::exchange(context, profile, loaded, &request, now, DebugSigning::off()) {
        Ok(exchanged) => {
            report.add(
                "Roles Anywhere authentication",
                Outcome::Pass(format!(
                    "session for {} expires {}",
                    exchanged
                        .assumed_role_arn
                        .as_deref()
                        .unwrap_or(&request.role_arn),
                    keystone_core::time::format_rfc3339(exchanged.credentials.expiration)
                )),
            );
        }
        Err(error) => {
            report.add(
                "Roles Anywhere authentication",
                Outcome::Fail(error.to_string()),
            );
        }
    }
}
