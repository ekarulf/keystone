//! Consumer adapter for google-cloud-auth 1.16.0. Copy into chromebook-control.
//! Requires tokio process/io-util/time, serde derive, serde_json, http, and anyhow.
use google_cloud_auth::credentials::{
    AccessToken, AccessTokenCredentials, AccessTokenCredentialsProvider, CacheableResource,
    CredentialsProvider,
};
use google_cloud_auth::errors::CredentialsError;
use serde::Deserialize;
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::AsyncReadExt;

const AUDIENCE: &str = "//iam.googleapis.com/projects/893698030930/locations/global/workloadIdentityPools/keystone-home/providers/aws-mac-mini";
const ACCOUNT: &str = "chromebook-control@karulf-home.iam.gserviceaccount.com";
const SCOPE: &str = "https://www.googleapis.com/auth/admin.directory.device.chromeos";
const EXECUTABLE: &str = "/Users/ekarulf/.local/bin/keystone";
const HOME: &str = "/Users/ekarulf/Library/Application Support/Keystone";
const PROFILE: &str = "chromebook";
const LIMIT: u64 = 65536;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(rename = "type")]
    kind: String,
    version: u8,
    executable: String,
    home: String,
    profile: String,
    audience: String,
    service_account_impersonation_url: String,
    scopes: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u8,
    profile: String,
    audience: String,
    service_account: String,
    scopes: Vec<String>,
    access_token: String,
    token_type: String,
    expires_at: u64,
}
#[derive(Debug)]
struct Keystone;

/// Preserve the existing service-account check, and add an explicit keystone_google
/// branch before external_account::Builder. Do not send this config to that builder.
pub fn credentials(path: &Path, account: &str) -> anyhow::Result<AccessTokenCredentials> {
    let config: Config = serde_json::from_slice(&read_config(path)?)
        .map_err(|_| anyhow::anyhow!("invalid Keystone configuration"))?;
    anyhow::ensure!(account == ACCOUNT && config.kind == "keystone_google" && config.version == 1
        && config.executable == EXECUTABLE && config.home == HOME && config.profile == PROFILE
        && config.audience == AUDIENCE && config.scopes == [SCOPE]
        && config.service_account_impersonation_url == format!("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{ACCOUNT}:generateAccessToken"),
        "Keystone credential policy mismatch");
    trusted(Path::new(EXECUTABLE))?;
    trusted(Path::new(HOME))?;
    Ok(Keystone.into())
}

#[cfg(unix)]
fn trusted(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "unsafe credential path"
    );
    // UID is deliberately supplied by the deployment's fixed home owner. The
    // executable and parent directories may also be root-owned, never writable
    // by other users. All services currently share this UID; no process boundary.
    let owner = std::fs::metadata(HOME)?.uid();
    for p in path.ancestors() {
        let m = std::fs::symlink_metadata(p)?;
        anyhow::ensure!(
            !m.file_type().is_symlink()
                && (m.uid() == owner || m.uid() == 0)
                && m.mode() & 0o022 == 0,
            "unsafe credential path"
        );
    }
    Ok(())
}
#[cfg(not(unix))]
fn trusted(_: &Path) -> anyhow::Result<()> {
    anyhow::bail!("Keystone Google adapter requires Unix")
}
fn read_config(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    trusted(path)?;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= LIMIT,
        "oversized credential configuration"
    );
    Ok(bytes)
}
fn error(transient: bool, message: &'static str) -> CredentialsError {
    CredentialsError::from_msg(transient, message)
}
impl AccessTokenCredentialsProvider for Keystone {
    async fn access_token(&self) -> Result<AccessToken, CredentialsError> {
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut child = tokio::process::Command::new(EXECUTABLE)
                .args(["--home", HOME, "google-token", "--profile", PROFILE])
                .kill_on_drop(true)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|_| error(false, "Keystone unavailable"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| error(false, "Keystone pipe unavailable"))?;
            let mut bytes = Vec::new();
            stdout
                .take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| error(true, "Keystone read failed"))?;
            if bytes.len() as u64 > LIMIT {
                return Err(error(false, "Oversized Keystone response"));
            }
            if !child
                .wait()
                .await
                .map_err(|_| error(true, "Keystone wait failed"))?
                .success()
            {
                return Err(error(true, "Keystone token acquisition failed"));
            }
            let r: Response = serde_json::from_slice(&bytes)
                .map_err(|_| error(false, "Malformed Keystone response"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| error(false, "Invalid clock"))?
                .as_secs();
            if r.version != 1
                || r.profile != PROFILE
                || r.audience != AUDIENCE
                || r.service_account != ACCOUNT
                || r.scopes != [SCOPE]
                || r.token_type != "Bearer"
                || r.expires_at <= now + 5
                || r.expires_at > now + 3660
                || r.access_token.is_empty()
                || r.access_token.len() > 16384
                || !r.access_token.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err(error(false, "Keystone token policy or expiry mismatch"));
            }
            Ok(AccessToken {
                token: r.access_token,
            })
        })
        .await
        .map_err(|_| error(true, "Keystone timed out"))?
    }
}
impl CredentialsProvider for Keystone {
    async fn headers(
        &self,
        _: http::Extensions,
    ) -> Result<CacheableResource<http::HeaderMap>, CredentialsError> {
        // Chromebook control calls access_token() exclusively.
        Err(error(
            false,
            "Keystone provider supports access tokens only",
        ))
    }
    async fn universe_domain(&self) -> Option<String> {
        Some("googleapis.com".into())
    }
}
