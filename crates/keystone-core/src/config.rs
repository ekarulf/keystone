//! Keystone configuration: `config.toml` and its validation rules.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{KeystoneError, Result};
use crate::identity::{KeyId, Sha256Fingerprint};
use crate::time::rfc3339;

/// The current configuration schema version.
pub const CONFIG_VERSION: u8 = 1;

/// Placeholder written into a generated profile before infrastructure exists.
///
/// `sync-profile` replaces these freely, but refuses to overwrite a real value
/// without `--force`.
pub const PLACEHOLDER: &str = "TBD";

fn is_placeholder(value: &str) -> bool {
    value.is_empty() || value == PLACEHOLDER
}

/// The root of `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u8,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            profiles: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self =
            toml::from_str(text).map_err(|e| KeystoneError::InvalidConfiguration(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn render(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| KeystoneError::InvalidConfiguration(e.to_string()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "configuration version {} is not supported (expected {CONFIG_VERSION})",
                self.version
            )));
        }
        for (name, profile) in &self.profiles {
            validate_profile_name(name)?;
            profile.validate(name)?;
        }
        Ok(())
    }

    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .get(name)
            .ok_or_else(|| KeystoneError::UnknownProfile(name.to_string()))
    }

    pub fn profile_mut(&mut self, name: &str) -> Result<&mut Profile> {
        self.profiles
            .get_mut(name)
            .ok_or_else(|| KeystoneError::UnknownProfile(name.to_string()))
    }
}

/// Profile names appear in file paths (cache entries, lock files, generated
/// directories), so they are restricted to characters that cannot traverse or
/// escape a path.
pub fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "profile name {name:?} must be between 1 and 64 characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "profile name {name:?} must contain only alphanumerics, '-', '_', or '.'"
        )));
    }
    if name.chars().all(|c| c == '.') {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "profile name {name:?} is not a usable directory name"
        )));
    }
    Ok(())
}

/// One named Keystone profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub region: String,

    #[serde(default)]
    pub trust_anchor_arn: String,
    #[serde(default)]
    pub roles_anywhere_profile_arn: String,
    #[serde(default)]
    pub role_arn: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_session_name: Option<String>,
    #[serde(default = "default_duration_seconds")]
    pub duration_seconds: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<KeyId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_fingerprint_sha256: Option<Sha256Fingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_fingerprint_sha256: Option<Sha256Fingerprint>,

    #[serde(default = "default_refresh_before_seconds")]
    pub refresh_before_seconds: u32,
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u32,
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u32,

    #[serde(default)]
    pub key_accessibility: KeyAccessibility,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerMetadata>,
}

fn default_duration_seconds() -> u32 {
    3600
}

fn default_refresh_before_seconds() -> u32 {
    300
}

fn default_connect_timeout_seconds() -> u32 {
    5
}

fn default_request_timeout_seconds() -> u32 {
    20
}

/// The shortest session AWS accepts for `CreateSession`.
pub const MIN_DURATION_SECONDS: u32 = 900;
/// The longest session IAM Roles Anywhere issues.
pub const MAX_DURATION_SECONDS: u32 = 3600;

impl Profile {
    /// Create a profile stub with no infrastructure wired up yet.
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            trust_anchor_arn: PLACEHOLDER.to_string(),
            roles_anywhere_profile_arn: PLACEHOLDER.to_string(),
            role_arn: PLACEHOLDER.to_string(),
            role_session_name: None,
            duration_seconds: default_duration_seconds(),
            key_id: None,
            certificate_fingerprint_sha256: None,
            ca_fingerprint_sha256: None,
            refresh_before_seconds: default_refresh_before_seconds(),
            connect_timeout_seconds: default_connect_timeout_seconds(),
            request_timeout_seconds: default_request_timeout_seconds(),
            key_accessibility: KeyAccessibility::default(),
            issuer: None,
        }
    }

    pub fn validate(&self, name: &str) -> Result<()> {
        if self.region.is_empty() {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "profile {name:?} has no region"
            )));
        }
        validate_region(&self.region)?;
        if self.duration_seconds < MIN_DURATION_SECONDS
            || self.duration_seconds > MAX_DURATION_SECONDS
        {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "profile {name:?} duration_seconds must be between {MIN_DURATION_SECONDS} and \
                 {MAX_DURATION_SECONDS}, found {}",
                self.duration_seconds
            )));
        }
        // A refresh window at or beyond the session lifetime would refresh on
        // every call, defeating the cache entirely.
        if self.refresh_before_seconds >= self.duration_seconds {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "profile {name:?} refresh_before_seconds ({}) must be less than \
                 duration_seconds ({})",
                self.refresh_before_seconds, self.duration_seconds
            )));
        }
        if self.connect_timeout_seconds == 0 || self.request_timeout_seconds == 0 {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "profile {name:?} timeouts must be greater than zero"
            )));
        }
        if let Some(session_name) = &self.role_session_name {
            validate_role_session_name(session_name)?;
        }
        Ok(())
    }

    /// Check every value needed to call `CreateSession` is present.
    ///
    /// Reported as one message listing all the gaps, so a freshly bootstrapped
    /// profile does not require several runs to discover what is missing.
    pub fn require_ready(&self, name: &str) -> Result<ReadyProfile<'_>> {
        let mut missing = Vec::new();
        if is_placeholder(&self.trust_anchor_arn) {
            missing.push("trust_anchor_arn");
        }
        if is_placeholder(&self.roles_anywhere_profile_arn) {
            missing.push("roles_anywhere_profile_arn");
        }
        if is_placeholder(&self.role_arn) {
            missing.push("role_arn");
        }
        if self.key_id.is_none() {
            missing.push("key_id");
        }
        if !missing.is_empty() {
            return Err(KeystoneError::ProfileIncomplete {
                profile: name.to_string(),
                reason: format!(
                    "missing {}; run `keystone infra cdk sync-profile --profile {name}` after \
                     deploying, or `keystone bootstrap --profile {name}` to create an identity",
                    missing.join(", ")
                ),
            });
        }
        Ok(ReadyProfile {
            trust_anchor_arn: &self.trust_anchor_arn,
            roles_anywhere_profile_arn: &self.roles_anywhere_profile_arn,
            role_arn: &self.role_arn,
            // Checked non-None above.
            key_id: self.key_id.as_ref().expect("key_id present"),
            region: &self.region,
            duration_seconds: self.duration_seconds,
            role_session_name: self.role_session_name.as_deref(),
        })
    }

    pub fn refresh_before(&self) -> time::Duration {
        time::Duration::seconds(i64::from(self.refresh_before_seconds))
    }
}

/// A profile proven to have everything `CreateSession` needs.
#[derive(Debug, Clone, Copy)]
pub struct ReadyProfile<'a> {
    pub trust_anchor_arn: &'a str,
    pub roles_anywhere_profile_arn: &'a str,
    pub role_arn: &'a str,
    pub key_id: &'a KeyId,
    pub region: &'a str,
    pub duration_seconds: u32,
    pub role_session_name: Option<&'a str>,
}

/// Region names are interpolated into the endpoint host, so they are checked
/// rather than trusted.
pub fn validate_region(region: &str) -> Result<()> {
    let plausible = !region.is_empty()
        && region.len() <= 32
        && region
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && region.starts_with(|c: char| c.is_ascii_lowercase())
        && !region.ends_with('-');
    if !plausible {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{region:?} is not a valid AWS region name"
        )));
    }
    Ok(())
}

/// IAM's constraint on `roleSessionName`, checked locally for a clearer error.
pub fn validate_role_session_name(name: &str) -> Result<()> {
    let valid = (2..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@-_".contains(c));
    if !valid {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "role_session_name {name:?} must be 2-64 characters of [A-Za-z0-9+=,.@_-]"
        )));
    }
    Ok(())
}

/// How the hardware key may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAccessibility {
    /// Signing works once the user has logged in after boot, including while
    /// the screen is locked. The default, because credential refresh has to
    /// work for unattended agents.
    #[default]
    AfterFirstUnlock,
    /// Signing works only while the device is unlocked.
    WhenUnlocked,
}

impl KeyAccessibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AfterFirstUnlock => "after-first-unlock",
            Self::WhenUnlocked => "when-unlocked",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::AfterFirstUnlock => "after first unlock, this device only",
            Self::WhenUnlocked => "while unlocked, this device only",
        }
    }
}

impl std::str::FromStr for KeyAccessibility {
    type Err = KeystoneError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "after-first-unlock" => Ok(Self::AfterFirstUnlock),
            "when-unlocked" => Ok(Self::WhenUnlocked),
            other => Err(KeystoneError::InvalidConfiguration(format!(
                "unknown key_accessibility {other:?} (expected \"after-first-unlock\" or \
                 \"when-unlocked\")"
            ))),
        }
    }
}

/// How the device certificate was issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssuerMode {
    /// A one-shot CA whose private key was destroyed after issuing.
    EphemeralCa,
    /// An external CA that still exists and can reissue.
    ExternalCa,
}

/// Recorded facts about the issuer, which determine whether renewal is possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    pub mode: IssuerMode,
    pub renewable: bool,
    pub trust_anchor_rotation_required: bool,
    #[serde(with = "rfc3339")]
    pub certificate_expires_at: OffsetDateTime,
}

impl IssuerMetadata {
    /// The issuer record for an ephemeral-CA identity.
    pub fn ephemeral(certificate_expires_at: OffsetDateTime) -> Self {
        Self {
            mode: IssuerMode::EphemeralCa,
            // The CA key no longer exists, so the certificate can never be reissued.
            renewable: false,
            trust_anchor_rotation_required: true,
            certificate_expires_at,
        }
    }
}

/// Where Keystone keeps its files.
///
/// Paths are grouped in one type so tests can redirect them to a temporary
/// directory instead of touching the user's real Application Support tree.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl Paths {
    /// The platform's standard locations, honoring `KEYSTONE_HOME` when set.
    pub fn discover() -> Result<Self> {
        if let Some(root) = std::env::var_os("KEYSTONE_HOME") {
            let root = PathBuf::from(root);
            return Ok(Self {
                cache_dir: root.join("cache"),
                data_dir: root,
            });
        }
        Self::platform_default()
    }

    /// The standard macOS locations, also used on any other non-Windows target.
    #[cfg(not(windows))]
    fn platform_default() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| KeystoneError::InvalidConfiguration("HOME is not set".to_string()))?;
        Ok(Self {
            data_dir: home.join("Library/Application Support/Keystone"),
            cache_dir: home.join("Library/Caches/Keystone"),
        })
    }

    /// The standard Windows locations.
    ///
    /// `%LOCALAPPDATA%`, not `%APPDATA%`. The roaming profile syncs to a file
    /// server, and a Keystone identity is bound to one machine's TPM: roaming it
    /// would copy an identity file to every machine the user signs in to, where the
    /// key it names does not exist. The cache goes under the same root in a
    /// separate subdirectory, since Windows has no distinct per-user cache
    /// location.
    #[cfg(windows)]
    fn platform_default() -> Result<Self> {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                KeystoneError::InvalidConfiguration(
                    "LOCALAPPDATA is not set, so Keystone cannot find its data directory; set \
                     KEYSTONE_HOME to choose one explicitly"
                        .to_string(),
                )
            })?;
        let root = local.join("Keystone");
        Ok(Self {
            cache_dir: root.join("cache"),
            data_dir: root,
        })
    }

    /// Paths rooted at an arbitrary directory, for tests.
    pub fn rooted_at(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            cache_dir: root.join("cache"),
            data_dir: root,
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.data_dir.join("config.toml")
    }

    pub fn identity_file(&self, key_id: &KeyId) -> PathBuf {
        self.data_dir
            .join("identities")
            .join(format!("{key_id}.json"))
    }

    pub fn identities_dir(&self) -> PathBuf {
        self.data_dir.join("identities")
    }

    pub fn certificate_dir(&self, fingerprint: &Sha256Fingerprint) -> PathBuf {
        self.data_dir
            .join("certificates")
            .join(fingerprint.as_str())
    }

    pub fn generated_dir(&self, profile: &str) -> PathBuf {
        self.data_dir.join("generated").join(profile)
    }

    pub fn credential_cache_file(&self, profile: &str) -> PathBuf {
        self.cache_dir
            .join("credentials")
            .join(format!("{profile}.json"))
    }

    pub fn lock_file(&self, profile: &str) -> PathBuf {
        self.cache_dir.join("locks").join(format!("{profile}.lock"))
    }
}

/// Directory mode for Keystone's own directories.
pub const DIR_MODE: u32 = 0o700;
/// File mode for Keystone's configuration and metadata.
pub const FILE_MODE: u32 = 0o600;

/// Reject a file another user could modify.
///
/// A writable config file lets another local user redirect Keystone at a role
/// or trust anchor of their choosing, so this is refused unless the caller
/// explicitly overrides it.
///
/// Three distinct ways another user can control the content, all checked:
///
/// * the file is group- or world-writable;
/// * the file belongs to someone else, who can change its mode back whenever they
///   like — a mode check alone reads their file as safe;
/// * the path is a symlink, since `std::fs::metadata` follows links and would
///   report the mode of a safe target rather than of the link, which its owner can
///   repoint at any moment.
///
/// The containing directory is deliberately *not* checked here. Keystone creates
/// its own directories 0700, and the caller-chosen output directories that
/// `write_atomic` also serves are the user's to share.
#[cfg(unix)]
pub fn check_not_group_or_world_writable(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // `symlink_metadata` does not follow links, so a link is visible as a link.
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| KeystoneError::io(format!("cannot inspect {}", path.display()), e))?;

    if metadata.file_type().is_symlink() {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} is a symbolic link. Keystone reads it only if it is a regular file, because \
             whoever owns the link can repoint it after this check; replace it with the file \
             itself or pass --allow-unsafe-permissions",
            path.display()
        )));
    }

    let mode = metadata.mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} is writable by other users (mode {mode:04o}); run `chmod {FILE_MODE:o} {}` or \
             pass --allow-unsafe-permissions",
            path.display(),
            path.display()
        )));
    }

    // Root is accepted as an owner: it can read and rewrite anything regardless,
    // so refusing a root-owned file would buy nothing and would break a Keystone
    // installed by an administrator.
    let owner = metadata.uid();
    let caller = rustix::process::geteuid().as_raw();
    if owner != caller && owner != 0 {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} is owned by uid {owner}, not by you (uid {caller}); its owner can change its \
             permissions at any time, so run `chown {caller} {}` or pass \
             --allow-unsafe-permissions",
            path.display(),
            path.display()
        )));
    }

    Ok(())
}

/// Reject a file another user could modify — the Windows form of the same check.
///
/// Windows has no mode bits, so the three Unix conditions become three questions
/// asked of the file's security descriptor:
///
/// * does anyone other than the caller hold write-equivalent access, which stands
///   in for group- and world-writable. "Write-equivalent" includes `WRITE_DAC`,
///   because a principal who can rewrite the ACL can grant itself write;
/// * is the caller the owner, since an owner can rewrite the DACL at will — the
///   direct analogue of the uid check;
/// * is the DACL absent, which grants *everyone* full control. It has no Unix
///   equivalent and is the most permissive state a file can be in, so it is
///   rejected outright.
///
/// The symlink case has no counterpart here. A Windows symbolic link requires
/// either administrator rights or Developer Mode to create, and a caller who
/// already has administrator rights can rewrite the file directly, so refusing
/// links would not close a path an attacker could otherwise use.
///
/// The Administrators group is accepted for the same reason root is accepted on
/// Unix: it can read and rewrite anything regardless, and refusing it would break a
/// Keystone installed for all users.
#[cfg(windows)]
pub fn check_not_group_or_world_writable(path: &Path) -> Result<()> {
    use keystone_win32_sys::security;

    let user = security::current_user_sid().map_err(|error| {
        KeystoneError::Other(format!("cannot determine the current user's SID: {error}"))
    })?;
    let access = security::file_access(path, &user).map_err(|error| {
        KeystoneError::Other(format!(
            "cannot inspect the permissions of {}: {error}",
            path.display()
        ))
    })?;

    if access.dacl_absent {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} has no access-control list, which grants every user full control. Reset its \
             permissions (for example with `icacls \"{}\" /reset /q` after removing inherited \
             entries) or pass --allow-unsafe-permissions",
            path.display(),
            path.display()
        )));
    }

    if access.other_writers > 0 {
        let others = access.other_writers;
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} is writable by {others} other principal(s); run \
             `icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"` or pass \
             --allow-unsafe-permissions",
            path.display(),
            path.display()
        )));
    }

    if !access.owner.matches(&user) && !security::is_administrators(&access.owner) {
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} is owned by another account; its owner can change its permissions at any time, so \
             run `icacls \"{}\" /setowner \"%USERNAME%\"` or pass --allow-unsafe-permissions",
            path.display(),
            path.display()
        )));
    }

    Ok(())
}

/// No permission model to check against, so nothing is claimed.
///
/// Reached only on a target that is neither Unix nor Windows, which Keystone does
/// not support: `keystone doctor` reports no available key store there, so this is
/// never the only thing standing between a caller and a hostile file.
#[cfg(not(any(unix, windows)))]
pub fn check_not_group_or_world_writable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 1

[profiles.personal]
region = "us-east-1"
trust_anchor_arn = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc"
roles_anywhere_profile_arn = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/def"
role_arn = "arn:aws:iam::123456789012:role/KeystonePersonalMac"
role_session_name = "example-laptop"
duration_seconds = 3600
key_id = "019cabc"
refresh_before_seconds = 300
key_accessibility = "after-first-unlock"

[profiles.personal.issuer]
mode = "ephemeral-ca"
renewable = false
trust_anchor_rotation_required = true
certificate_expires_at = "2031-07-25T00:00:00Z"
"#;

    #[test]
    fn a_complete_configuration_parses() {
        let config = Config::parse(SAMPLE).unwrap();
        let profile = config.profile("personal").unwrap();
        assert_eq!(profile.region, "us-east-1");
        assert_eq!(profile.duration_seconds, 3600);
        assert_eq!(
            profile.key_accessibility,
            KeyAccessibility::AfterFirstUnlock
        );
        let issuer = profile.issuer.as_ref().unwrap();
        assert_eq!(issuer.mode, IssuerMode::EphemeralCa);
        assert!(!issuer.renewable);
    }

    #[test]
    fn configuration_round_trips_through_toml() {
        let config = Config::parse(SAMPLE).unwrap();
        let rendered = config.render().unwrap();
        let reparsed = Config::parse(&rendered).unwrap();
        assert_eq!(
            reparsed.profile("personal").unwrap().role_arn,
            config.profile("personal").unwrap().role_arn
        );
    }

    #[test]
    fn optional_settings_fall_back_to_documented_defaults() {
        let config = Config::parse(
            r#"
            version = 1
            [profiles.minimal]
            region = "us-west-2"
        "#,
        )
        .unwrap();
        let profile = config.profile("minimal").unwrap();
        assert_eq!(profile.duration_seconds, 3600);
        assert_eq!(profile.refresh_before_seconds, 300);
        assert_eq!(profile.connect_timeout_seconds, 5);
        assert_eq!(profile.request_timeout_seconds, 20);
        assert_eq!(
            profile.key_accessibility,
            KeyAccessibility::AfterFirstUnlock
        );
    }

    #[test]
    fn a_future_configuration_version_is_refused() {
        let text = SAMPLE.replace("version = 1", "version = 2");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn a_missing_profile_is_reported_by_name() {
        let config = Config::parse(SAMPLE).unwrap();
        assert!(matches!(
            config.profile("nope"),
            Err(KeystoneError::UnknownProfile(name)) if name == "nope"
        ));
    }

    #[test]
    fn configuration_never_contains_credential_fields() {
        // Guards the invariant that config.toml holds no secrets: unknown keys
        // like these would be silently ignored, so assert they are absent.
        let rendered = Config::parse(SAMPLE).unwrap().render().unwrap();
        for forbidden in [
            "aws_access_key_id",
            "aws_secret_access_key",
            "session_token",
            "private_key",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "{forbidden} leaked into config"
            );
        }
    }

    #[test]
    fn durations_outside_the_aws_range_are_refused() {
        for duration in [0, 60, 899, 3601, 43200] {
            let text = SAMPLE.replace(
                "duration_seconds = 3600",
                &format!("duration_seconds = {duration}"),
            );
            assert!(Config::parse(&text).is_err(), "should reject {duration}");
        }
    }

    #[test]
    fn a_refresh_window_longer_than_the_session_is_refused() {
        let text = SAMPLE.replace(
            "refresh_before_seconds = 300",
            "refresh_before_seconds = 3600",
        );
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn zero_timeouts_are_refused() {
        let text = SAMPLE.replace(
            "duration_seconds = 3600",
            "duration_seconds = 3600\nconnect_timeout_seconds = 0",
        );
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn implausible_regions_are_refused() {
        for region in ["", "US-EAST-1", "us east 1", "us-east-1/../x", "us-east-"] {
            let text = SAMPLE.replace("region = \"us-east-1\"", &format!("region = \"{region}\""));
            assert!(Config::parse(&text).is_err(), "should reject {region:?}");
        }
    }

    #[test]
    fn profile_names_that_could_escape_a_path_are_refused() {
        for name in ["..", "has/slash", "has space", ""] {
            assert!(
                validate_profile_name(name).is_err(),
                "should reject {name:?}"
            );
        }
        for name in ["personal", "work-2", "team_a", "v1.2"] {
            validate_profile_name(name).unwrap();
        }
    }

    #[test]
    fn role_session_names_follow_the_iam_character_set() {
        validate_role_session_name("example-laptop").unwrap();
        assert!(validate_role_session_name("a").is_err());
        assert!(validate_role_session_name("has space").is_err());
        assert!(validate_role_session_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn a_ready_profile_exposes_everything_create_session_needs() {
        let config = Config::parse(SAMPLE).unwrap();
        let ready = config
            .profile("personal")
            .unwrap()
            .require_ready("personal")
            .unwrap();
        assert_eq!(ready.region, "us-east-1");
        assert_eq!(ready.duration_seconds, 3600);
        assert_eq!(ready.role_session_name, Some("example-laptop"));
    }

    #[test]
    fn an_unsynced_profile_lists_every_missing_value_at_once() {
        let profile = Profile::new("us-east-1");
        let error = profile.require_ready("personal").unwrap_err();
        let message = error.to_string();
        for expected in [
            "trust_anchor_arn",
            "roles_anywhere_profile_arn",
            "role_arn",
            "key_id",
        ] {
            assert!(message.contains(expected), "{message}");
        }
        // And it says what to do about it.
        assert!(message.contains("sync-profile"), "{message}");
    }

    #[test]
    fn key_accessibility_round_trips_through_its_wire_form() {
        for value in [
            KeyAccessibility::AfterFirstUnlock,
            KeyAccessibility::WhenUnlocked,
        ] {
            assert_eq!(value.as_str().parse::<KeyAccessibility>().unwrap(), value);
        }
        assert!("touch-id".parse::<KeyAccessibility>().is_err());
    }

    #[test]
    fn ephemeral_issuers_are_never_renewable() {
        let issuer = IssuerMetadata::ephemeral(time::macros::datetime!(2031-07-25 0:00 UTC));
        assert!(!issuer.renewable);
        assert!(issuer.trust_anchor_rotation_required);
    }

    #[test]
    fn paths_are_derived_from_one_root() {
        let paths = Paths::rooted_at("/tmp/keystone-test");
        assert_eq!(
            paths.config_file(),
            PathBuf::from("/tmp/keystone-test/config.toml")
        );
        assert_eq!(
            paths.lock_file("personal"),
            PathBuf::from("/tmp/keystone-test/cache/locks/personal.lock")
        );
        assert_eq!(
            paths.credential_cache_file("personal"),
            PathBuf::from("/tmp/keystone-test/cache/credentials/personal.json")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_world_writable_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("keystone-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "version = 1").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        check_not_group_or_world_writable(&path).unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let error = check_not_group_or_world_writable(&path).unwrap_err();
        assert!(error.to_string().contains("writable by other users"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
