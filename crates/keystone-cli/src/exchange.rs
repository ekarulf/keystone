//! The credential exchange, with the cache and lock the design specifies.
//!
//! The V1 flow, from the design:
//!
//! 1. Read cache. 2. Return if sufficiently fresh. 3. Acquire profile lock.
//! 4. Read cache again. 5. Return if another process refreshed it.
//! 6. Call Roles Anywhere. 7. Atomically update cache. 8. Release lock.
//!
//! Two consequences are worth stating, because getting either wrong is invisible
//! in casual testing: the *second* cache read is what stops a burst of concurrent
//! SDK processes from each performing its own `CreateSession`, and "a refresh
//! failure should not discard cached credentials that are still valid" means a
//! network error falls back to a cache entry that has not actually expired rather
//! than failing the command.

use std::path::Path;

use crate::backend::CertificateIdentity;
use keystone_core::config::Profile;
use keystone_core::credentials::{AwsSessionCredentials, CachedCredentials};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::store::{write_atomic, Store};
use keystone_core::time::FixedClock;
use keystone_roles_anywhere::client::{AttemptRecord, TransportConfig};
use keystone_roles_anywhere::{CreateSessionRequest, RolesAnywhereClient, SignedRequest};
use time::OffsetDateTime;

use crate::context::Context;
use crate::identity::LoadedIdentity;

/// Where a credential set came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    /// Served from the on-disk cache without contacting AWS.
    Cache,
    /// Obtained from a fresh `CreateSession`.
    Exchange,
    /// A cached entry that has not expired, served because a refresh failed.
    CacheAfterFailedRefresh,
}

/// The outcome of a credential request.
pub struct Exchanged {
    pub credentials: AwsSessionCredentials,
    pub source: CredentialSource,
    /// The role AWS reported, when it reported one.
    pub assumed_role_arn: Option<String>,
    /// One record per HTTP attempt, for `--verbose` and `keystone doctor`.
    pub attempts: Vec<AttemptRecord>,
}

/// How the caller wants signing diagnostics handled.
#[derive(Debug, Clone, Copy)]
pub struct DebugSigning {
    pub enabled: bool,
    pub redact: bool,
}

impl DebugSigning {
    pub fn off() -> Self {
        Self {
            enabled: false,
            redact: true,
        }
    }
}

/// Build the request body for a profile.
///
/// `require_ready` is what refuses a profile whose ARNs are still `TBD`, so the
/// error names the missing field instead of AWS rejecting an ARN of `"TBD"`.
pub fn session_request(profile_name: &str, profile: &Profile) -> Result<CreateSessionRequest> {
    let ready = profile.require_ready(profile_name)?;
    Ok(CreateSessionRequest {
        profile_arn: ready.roles_anywhere_profile_arn.to_string(),
        role_arn: ready.role_arn.to_string(),
        trust_anchor_arn: ready.trust_anchor_arn.to_string(),
        duration_seconds: ready.duration_seconds,
        role_session_name: ready.role_session_name.map(str::to_string),
    })
}

/// Obtain credentials for a profile, using and updating the cache.
pub fn credentials_for(
    context: &Context,
    profile_name: &str,
    profile: &Profile,
    loaded: &LoadedIdentity,
    now: OffsetDateTime,
    use_cache: bool,
    debug: DebugSigning,
) -> Result<Exchanged> {
    let request = session_request(profile_name, profile)?;
    let cache_path = context.store.paths().credential_cache_file(profile_name);

    if use_cache {
        if let Some(cached) = read_fresh_cache(context, &cache_path, profile_name, profile, now) {
            context.detail(format!(
                "using cached credentials, expiring {}",
                keystone_core::time::format_rfc3339(cached.expiration)
            ));
            return Ok(Exchanged {
                credentials: cached,
                source: CredentialSource::Cache,
                assumed_role_arn: None,
                attempts: Vec::new(),
            });
        }
    }

    // Steps 3 to 5: hold the lock across the refresh, and re-read the cache once
    // it is held. Without the second read, ten SDK processes starting together
    // perform ten exchanges; with it, one exchanges and nine read its result.
    let _lock = ProfileLock::acquire(&context.store, profile_name)?;
    if use_cache {
        if let Some(cached) = read_fresh_cache(context, &cache_path, profile_name, profile, now) {
            context.detail("another process refreshed the credentials while waiting for the lock");
            return Ok(Exchanged {
                credentials: cached,
                source: CredentialSource::Cache,
                assumed_role_arn: None,
                attempts: Vec::new(),
            });
        }
    }

    match exchange(context, profile, loaded, &request, now, debug) {
        Ok(exchanged) => {
            if use_cache {
                // Best effort: credentials in hand are more useful than a failed
                // command, and the next invocation will simply exchange again.
                if let Err(error) = write_cache(
                    &cache_path,
                    &exchanged.credentials,
                    profile_name,
                    &request.role_arn,
                ) {
                    context.detail(format!("could not update the credential cache: {error}"));
                }
            }
            Ok(exchanged)
        }
        Err(error) => {
            // "A refresh failure should not discard cached credentials that are
            // still valid." An entry inside its refresh window is past the point
            // where Keystone prefers to refresh, but it is not expired.
            if use_cache {
                if let Some(cached) =
                    read_unexpired_cache(context, &cache_path, profile_name, &request, now)
                {
                    context.note(format!(
                        "warning: could not refresh credentials ({error}); using cached \
                         credentials that expire at {}",
                        keystone_core::time::format_rfc3339(cached.expiration)
                    ));
                    return Ok(Exchanged {
                        credentials: cached,
                        source: CredentialSource::CacheAfterFailedRefresh,
                        assumed_role_arn: None,
                        attempts: Vec::new(),
                    });
                }
            }
            Err(error)
        }
    }
}

/// Perform one `CreateSession` exchange, with no cache involvement.
pub fn exchange(
    context: &Context,
    profile: &Profile,
    loaded: &LoadedIdentity,
    request: &CreateSessionRequest,
    now: OffsetDateTime,
    debug: DebugSigning,
) -> Result<Exchanged> {
    // A fixed clock, set to the timestamp this command already validated: the
    // design requires one timestamp per signing attempt, used consistently.
    let client = client_for(profile, &loaded.identity, now)?;

    if debug.enabled {
        let signed = client.sign_now(request)?;
        emit_signing_debug(context, &signed, debug.redact);
    }

    let mut attempts = Vec::new();
    let result = client.create_session_recording(request, &mut attempts)?;
    result.credentials.validate(now)?;

    if let Some(assumed) = &result.assumed_role_arn {
        check_assumed_role(assumed, &request.role_arn)?;
    }

    Ok(Exchanged {
        credentials: result.credentials,
        source: CredentialSource::Exchange,
        assumed_role_arn: result.assumed_role_arn,
        attempts,
    })
}

/// Build a client bound to this identity, region, and timestamp.
fn client_for<'a>(
    profile: &Profile,
    identity: &'a CertificateIdentity,
    now: OffsetDateTime,
) -> Result<RolesAnywhereClient<&'a CertificateIdentity, FixedClock>> {
    RolesAnywhereClient::new(
        identity,
        profile.region.clone(),
        FixedClock(now),
        TransportConfig::from_profile(profile),
    )
}

/// Confirm the session AWS returned is for the role that was requested.
///
/// The design asks for this check "when that metadata is available". A mismatch
/// means the Roles Anywhere profile maps to a different role than the local
/// configuration believes, which would otherwise show up as puzzling
/// authorization failures in whatever used the credentials.
fn check_assumed_role(assumed: &str, requested_role_arn: &str) -> Result<()> {
    // Compared as a whole path segment, not as a substring. `contains` accepts
    // every role whose name merely embeds the requested one — `KeystonePersonal`
    // matches `KeystonePersonalAdmin` — and also matches when the name appears in
    // the session-name position, so a session named after the role would satisfy
    // the check no matter which role was actually assumed.
    let requested = requested_role_arn.rsplit('/').next().unwrap_or_default();
    if requested.is_empty() {
        return Ok(());
    }
    match assumed_role_name(assumed) {
        // The design asks for this check "when that metadata is available", and an
        // ARN in a shape Keystone does not recognize is a case where it is not.
        // Failing here would break credentials over an unrecognized ARN format
        // rather than over a real mismatch.
        None => Ok(()),
        Some(actual) if actual == requested => Ok(()),
        Some(_) => Err(KeystoneError::InvalidCredentialResponse(format!(
            "IAM Roles Anywhere returned a session for {assumed}, which is not the requested role \
             {requested_role_arn}. Check which role the Roles Anywhere profile maps to."
        ))),
    }
}

/// The role name from an STS assumed-role ARN.
///
/// `arn:aws:sts::123456789012:assumed-role/<role>/<session>` — the shape AWS
/// returns in `assumedRoleUser.arn`. A role with an IAM path loses that path here,
/// which is why this is compared against the requested ARN's last segment rather
/// than against its full resource.
fn assumed_role_name(assumed: &str) -> Option<&str> {
    let resource = assumed.split(':').nth(5)?;
    let rest = resource.strip_prefix("assumed-role/")?;
    // A session name may itself contain no `/`, so the role is everything up to
    // the first separator.
    let name = rest.split('/').next()?;
    (!name.is_empty()).then_some(name)
}

/// Print the canonical request and string-to-sign to standard error.
fn emit_signing_debug(context: &Context, signed: &SignedRequest, redact: bool) {
    context.note("--- canonical request ---");
    context.note(&signed.canonical_request);
    context.note("--- string to sign ---");
    context.note(&signed.string_to_sign);
    context.note("--- request ---");
    context.note(signed.to_redacted_string());
    if !redact {
        // `--redact false` widens what is shown to the full certificate headers,
        // which are public. The authorization signature still is not printed: it
        // is not needed to debug canonicalization, and it is a replayable
        // credential until its timestamp ages out.
        for (name, value) in &signed.headers {
            if name.eq_ignore_ascii_case("x-amz-x509")
                || name.eq_ignore_ascii_case("x-amz-x509-chain")
            {
                context.note(format!("{name}: {value}"));
            }
        }
        context.note(
            "note: the authorization signature stays redacted. Compare the canonical request \
             and string-to-sign above instead.",
        );
    }
}

/// Read the cache, returning credentials only if they need no refresh.
fn read_fresh_cache(
    context: &Context,
    path: &Path,
    profile_name: &str,
    profile: &Profile,
    now: OffsetDateTime,
) -> Option<AwsSessionCredentials> {
    let cached = load_cache(context, path)?;
    let role_arn = cached.role_arn.clone();
    let credentials = match cached.to_credentials(profile_name, &role_arn) {
        Ok(credentials) => credentials,
        Err(error) => {
            context.detail(format!("ignoring the credential cache: {error}"));
            return None;
        }
    };
    // A cache entry for a role the profile no longer names must not be served.
    if role_arn != profile.role_arn {
        context.detail("ignoring the credential cache: it was written for a different role");
        return None;
    }
    if credentials.needs_refresh(now, profile.refresh_before()) {
        return None;
    }
    Some(credentials)
}

/// Read the cache, accepting any entry that has not yet expired.
fn read_unexpired_cache(
    context: &Context,
    path: &Path,
    profile_name: &str,
    request: &CreateSessionRequest,
    now: OffsetDateTime,
) -> Option<AwsSessionCredentials> {
    let cached = load_cache(context, path)?;
    let credentials = cached
        .to_credentials(profile_name, &request.role_arn)
        .ok()?;
    // `validate` rejects an expiration in the past, which is exactly the line
    // between "still usable" and "no better than nothing".
    credentials.validate(now).ok()?;
    Some(credentials)
}

/// Read and parse a cache entry, or `None` for any reason it cannot be trusted.
///
/// The permission check matters more here than for the other files Keystone
/// reads: those hold public material whose substitution `restore` and the
/// certificate pairing would catch, whereas this file holds a live secret access
/// key and session token. A cache another user can write is a cache another user
/// can *plant*, which would hand the AWS SDK credentials of their choosing.
///
/// A failed check downgrades to "no cache" rather than an error, matching the
/// rest of this function: an unreadable or corrupt entry means Keystone
/// exchanges again, and refusing to produce credentials at all would be a worse
/// outcome than ignoring the file. The reason is reported under `--verbose`, so
/// the permission problem is still discoverable — and `keystone doctor` reports
/// it unconditionally.
fn load_cache(context: &Context, path: &Path) -> Option<CachedCredentials> {
    if let Err(error) = context.store.check_trusted(path) {
        context.detail(format!("ignoring the credential cache: {error}"));
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Write the cache atomically, with owner-only permissions.
fn write_cache(
    path: &Path,
    credentials: &AwsSessionCredentials,
    profile_name: &str,
    role_arn: &str,
) -> Result<()> {
    let cached = CachedCredentials::new(credentials, profile_name, role_arn);
    let json = serde_json::to_vec(&cached).map_err(|error| {
        KeystoneError::Other(format!("cannot serialize the cache entry: {error}"))
    })?;
    // The cache holds a live secret access key, so the directory is 0700 and the
    // file is created 0600 before anything is written to it — the secret is never
    // briefly readable by another user.
    if let Some(parent) = path.parent() {
        keystone_core::store::create_dir_all_private(parent)?;
    }
    write_atomic(path, &json)
}

/// A per-profile advisory lock, held for the duration of a refresh.
///
/// Failure to take the lock is not fatal by design: a duplicate `CreateSession`
/// costs one extra request, whereas refusing to produce credentials because a
/// lock file could not be created would break the AWS SDK integration for no
/// security benefit. The lock releases when the file handle drops, including on
/// a panic or a kill, so a crashed refresh cannot wedge later invocations.
struct ProfileLock {
    file: Option<std::fs::File>,
}

impl ProfileLock {
    fn acquire(store: &Store, profile_name: &str) -> Result<Self> {
        let path = store.paths().lock_file(profile_name);
        if let Some(parent) = path.parent() {
            keystone_core::store::create_dir_all_private(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .ok();
        if let Some(file) = &file {
            // Blocking: the waiter wants the credentials the holder is about to
            // write, so waiting is the useful behavior, and the request timeout
            // bounds how long the holder can take.
            let _ = fs2::FileExt::lock_exclusive(file);
        }
        Ok(Self { file })
    }
}

impl Drop for ProfileLock {
    fn drop(&mut self) {
        if let Some(file) = &self.file {
            let _ = fs2::FileExt::unlock(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keystone_core::config::Profile;

    fn profile() -> Profile {
        let mut profile = Profile::new("us-east-1");
        profile.trust_anchor_arn =
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/1111".to_string();
        profile.roles_anywhere_profile_arn =
            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/2222".to_string();
        profile.role_arn = "arn:aws:iam::123456789012:role/KeystonePersonal".to_string();
        profile.key_id = Some(keystone_core::identity::KeyId::parse("01JZDEVICE").unwrap());
        profile
    }

    #[test]
    fn a_request_carries_the_three_arns_and_the_duration() {
        let request = session_request("personal", &profile()).unwrap();
        assert!(request.profile_arn.contains(":profile/"));
        assert!(request.trust_anchor_arn.contains(":trust-anchor/"));
        assert!(request.role_arn.contains(":role/"));
        assert_eq!(request.duration_seconds, 3600);
    }

    #[test]
    fn a_profile_with_placeholder_arns_is_refused_before_any_request() {
        // The error should name `sync-profile`, not produce an AWS rejection of an
        // ARN of "TBD".
        let mut incomplete = profile();
        incomplete.role_arn = keystone_core::config::PLACEHOLDER.to_string();
        let error = session_request("personal", &incomplete).unwrap_err();
        assert!(
            matches!(error, KeystoneError::ProfileIncomplete { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_session_for_another_role_is_rejected() {
        // The design's "the returned role is compatible with the requested role,
        // when that metadata is available".
        let requested = "arn:aws:iam::123456789012:role/KeystonePersonal";
        check_assumed_role(
            "arn:aws:sts::123456789012:assumed-role/KeystonePersonal/example-laptop",
            requested,
        )
        .unwrap();

        let error = check_assumed_role(
            "arn:aws:sts::123456789012:assumed-role/SomethingElse/example-laptop",
            requested,
        )
        .unwrap_err();
        assert!(format!("{error}").contains("SomethingElse"), "{error}");
    }

    #[test]
    fn a_role_whose_name_merely_contains_the_requested_one_is_rejected() {
        // The case a `contains` check accepts. `KeystonePersonalAdmin` is a
        // different role with different permissions, and the name of the requested
        // role is a prefix of it — so this is the mismatch most likely to be a real
        // misconfiguration rather than a typo.
        let requested = "arn:aws:iam::123456789012:role/KeystonePersonal";
        for actual in [
            "arn:aws:sts::123456789012:assumed-role/KeystonePersonalAdmin/example-laptop",
            "arn:aws:sts::123456789012:assumed-role/NotKeystonePersonal/example-laptop",
            // The role name in the session-name position: the assumed role is
            // something else entirely, and only segment-wise parsing notices.
            "arn:aws:sts::123456789012:assumed-role/SomethingElse/KeystonePersonal",
        ] {
            assert!(
                check_assumed_role(actual, requested).is_err(),
                "should be rejected: {actual}"
            );
        }
    }

    #[test]
    fn an_unrecognized_assumed_role_arn_does_not_fail_the_exchange() {
        // "when that metadata is available" — credentials that work must not be
        // discarded because the ARN was not in the shape this parser expects.
        let requested = "arn:aws:iam::123456789012:role/KeystonePersonal";
        for actual in [
            "",
            "not-an-arn",
            "arn:aws:sts::123456789012:federated-user/x",
        ] {
            assert!(
                check_assumed_role(actual, requested).is_ok(),
                "should be tolerated: {actual:?}"
            );
        }
    }

    #[test]
    fn a_role_with_an_iam_path_still_matches() {
        // IAM paths do not appear in the STS assumed-role ARN, so comparing the
        // full resource would reject a correct session.
        check_assumed_role(
            "arn:aws:sts::123456789012:assumed-role/KeystonePersonal/example-laptop",
            "arn:aws:iam::123456789012:role/keystone/devices/KeystonePersonal",
        )
        .unwrap();
    }
}
