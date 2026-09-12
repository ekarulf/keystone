//! Scoped Google token minting over renewable Roles Anywhere credentials.
//! No subject assertion or intermediate token is exposed to the caller.
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use keystone_core::config::{Config, GooglePolicy};
use keystone_core::credentials::{AwsSessionCredentials, CredentialProcessOutput};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::store::write_atomic;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    cli::ProfileArgs,
    context::{print_line, Context},
};

const MAX_DOCUMENT: u64 = 65536;
const REFRESH_MARGIN: i64 = 60;
const TOKEN_TYPE: &str = "urn:ietf:params:aws:token-type:aws4_request";
const STS: &str = "https://sts.googleapis.com/v1/token";

fn fail(class: &str) -> KeystoneError {
    KeystoneError::Other(format!("Google credentials: {class}"))
}

/// This is a private process protocol, not a Google executable-source response.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    version: u8,
    profile: String,
    audience: String,
    service_account: String,
    scopes: Vec<String>,
    access_token: String,
    token_type: String,
    expires_at: i64,
}
impl Drop for Token {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GoogleToken(<redacted>)")
    }
}
impl Token {
    fn validate(&self, name: &str, policy: &GooglePolicy, now: i64) -> Result<()> {
        if self.version != 1
            || self.profile != name
            || self.audience != policy.audience
            || self.service_account != policy.service_account
            || self.scopes != policy.scopes
            || self.token_type != "Bearer"
            || !valid_token(&self.access_token)
            || self.expires_at <= now
            || self.expires_at > now + 3660
        {
            return Err(fail("invalid token response or policy mismatch"));
        }
        Ok(())
    }
}
fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 16384 && token.bytes().all(|b| b.is_ascii_graphic())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cache {
    binding: String,
    retry_after: i64,
    token: Option<Token>,
}

// Every path component must be trusted before a child is opened. Sticky system
// temporary directories are allowed as ancestors, but never as the private leaf.
fn check_path(path: &Path, private: bool) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(fail("unsafe path"));
    }
    for p in path.ancestors() {
        let m = std::fs::symlink_metadata(p).map_err(|_| fail("missing or unsafe path"))?;
        let uid = rustix::process::geteuid().as_raw();
        if m.file_type().is_symlink()
            || (m.uid() != uid && m.uid() != 0)
            || (m.mode() & 0o022 != 0
                && !(p != path && m.is_dir() && m.uid() == 0 && m.mode() & 0o1000 != 0))
            || (p == path && private && (m.uid() != uid || m.mode() & 0o077 != 0))
        {
            return Err(fail("unsafe ownership, permissions, or symlink"));
        }
    }
    Ok(())
}
fn open_private(path: &Path, create: bool) -> Result<File> {
    check_path(path.parent().ok_or_else(|| fail("unsafe path"))?, true)?;
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        // A FIFO can block in open(), before the handle can be inspected.
        // NONBLOCK permits fstat to reject it without waiting for a writer.
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|_| fail("cannot open private file"))?;
    let m = file
        .metadata()
        .map_err(|_| fail("cannot inspect private file"))?;
    if !m.is_file()
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(fail("unsafe private file"));
    }
    Ok(file)
}
fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    open_private(path, false)?
        .take(MAX_DOCUMENT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("cannot read private file"))?;
    if bytes.len() as u64 > MAX_DOCUMENT {
        return Err(fail("oversized private file"));
    }
    Ok(bytes)
}
fn lock(file: &File, deadline: Instant) -> Result<()> {
    loop {
        match fs2::FileExt::try_lock_exclusive(file) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(fail("refresh lock failed")),
        }
        if Instant::now() >= deadline {
            return Err(fail("refresh lock timeout"));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn run(context: &Context, args: &ProfileArgs) -> Result<()> {
    keystone_core::config::validate_profile_name(&args.profile)?;
    run_inner(context, args)
        .map_err(|error| KeystoneError::Other(format!("Google profile {}: {error}", args.profile)))
}

fn run_inner(context: &Context, args: &ProfileArgs) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(18);
    // Unlike the general AWS CLI, Google never honors --allow-unsafe-permissions.
    let config_path = context.store.paths().config_file();
    let root = config_path
        .parent()
        .ok_or_else(|| fail("missing Keystone root"))?;
    check_path(root, true)?;
    let text = read_file(&config_path)?;
    let config =
        Config::parse(std::str::from_utf8(&text).map_err(|_| fail("invalid configuration"))?)
            .map_err(|_| fail("invalid configuration"))?;
    let profile = config.profile(&args.profile)?;
    let policy = profile
        .google
        .as_ref()
        .ok_or_else(|| fail("profile has no Google policy"))?;
    profile.require_ready(&args.profile)?;
    let dir = root.join("google-cache");
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(fail("cannot create Google cache directory")),
    }
    check_path(&dir, true)?;
    let lock_file = open_private(&dir.join(format!("{}.lock", args.profile)), true)?;
    lock(&lock_file, deadline)?;
    let path = dir.join(format!("{}.json", args.profile));
    // Bind the cache to the complete AWS profile, including key and trust changes.
    let binding = hex::encode(Sha256::digest(
        serde_json::to_vec(profile).map_err(|_| fail("invalid policy"))?,
    ));
    let token = cached_or_refresh(
        &path,
        &binding,
        &args.profile,
        policy,
        || context.now().unix_timestamp(),
        || {
            let aws = aws_credentials(root, &args.profile, deadline)?;
            let now = context.now_checked()?;
            let subject = subject_token(&aws, &profile.region, policy, now)?;
            let http = reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .build()
                .map_err(|_| fail("HTTP client unavailable"))?;
            mint(
                &args.profile,
                policy,
                &subject,
                now.unix_timestamp(),
                |stage, body, bearer| {
                    let endpoint = if stage == "STS" {
                        STS.to_owned()
                    } else {
                        policy.impersonation_url()
                    };
                    let remaining = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| fail("exchange timeout"))?;
                    let mut request = http.post(endpoint).timeout(remaining).json(body);
                    if let Some(token) = bearer {
                        request = request.bearer_auth(token);
                    }
                    let response = request
                        .send()
                        .map_err(|_| fail(&format!("{stage} transport failure")))?;
                    let status = response.status();
                    if !status.is_success() {
                        // Never propagate response bodies, URLs, headers or reqwest errors.
                        return Err(fail(&format!("{stage} HTTP {}", status.as_u16())));
                    }
                    let mut bytes = Zeroizing::new(Vec::new());
                    response
                        .take(MAX_DOCUMENT + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|_| fail("response read failed"))?;
                    if bytes.len() as u64 > MAX_DOCUMENT {
                        return Err(fail("oversized HTTP response"));
                    }
                    serde_json::from_slice(&bytes).map_err(|_| fail("malformed HTTP response"))
                },
            )
        },
    )?;
    token.validate(&args.profile, policy, context.now().unix_timestamp())?;
    context.detail(format!("Google profile {}: token ready", args.profile));
    let document =
        Zeroizing::new(serde_json::to_string(&token).map_err(|_| fail("serialization failed"))?);
    print_line(&document)
}
use std::os::unix::fs::DirBuilderExt;

fn cached_or_refresh(
    path: &Path,
    binding: &str,
    name: &str,
    policy: &GooglePolicy,
    now: impl Fn() -> i64,
    refresh: impl FnOnce() -> Result<Token>,
) -> Result<Token> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            let bytes = read_file(path)?;
            let cached: Cache =
                serde_json::from_slice(&bytes).map_err(|_| fail("malformed Google cache"))?;
            if cached.binding == binding {
                if cached.retry_after > now() {
                    return Err(fail("refresh backoff; retry later"));
                }
                if let Some(token) = cached.token {
                    if token.validate(name, policy, now()).is_ok()
                        && token.expires_at > now() + REFRESH_MARGIN
                    {
                        return Ok(token);
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(fail("cannot inspect Google cache")),
    }
    let result = refresh().and_then(|token| {
        token.validate(name, policy, now())?;
        if token.expires_at <= now() + REFRESH_MARGIN {
            return Err(fail("new token expires inside refresh margin"));
        }
        Ok(token)
    });
    let cached = Cache {
        binding: binding.into(),
        retry_after: if result.is_err() { now() + 5 } else { 0 },
        token: result.as_ref().ok().map(|t| Token {
            version: t.version,
            profile: t.profile.clone(),
            audience: t.audience.clone(),
            service_account: t.service_account.clone(),
            scopes: t.scopes.clone(),
            access_token: t.access_token.clone(),
            token_type: t.token_type.clone(),
            expires_at: t.expires_at,
        }),
    };
    let bytes = Zeroizing::new(
        serde_json::to_vec(&cached).map_err(|_| fail("cache serialization failed"))?,
    );
    write_atomic(path, &bytes).map_err(|_| fail("cache write failed"))?;
    result
}

// A subprocess bounds both hardware access and the existing AWS profile lock.
// Read stdout concurrently with a size limit; discard stderr, including on errors.
fn aws_credentials(root: &Path, name: &str, deadline: Instant) -> Result<AwsSessionCredentials> {
    let mut child = Command::new(std::env::current_exe().map_err(|_| fail("helper unavailable"))?)
        .arg("--home")
        .arg(root)
        .arg("credential-process")
        .arg("--profile")
        .arg(name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| fail("AWS helper unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| fail("AWS helper pipe unavailable"))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        stdout
            .take(MAX_DOCUMENT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let aws_deadline = deadline.min(Instant::now() + Duration::from_secs(10));
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < aws_deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(fail("AWS helper timeout or wait failure"));
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| fail("AWS helper read failure"))?
        .map_err(|_| fail("AWS helper read failure"))?;
    if !status?.success() {
        return Err(fail("AWS credential acquisition failed"));
    }
    parse_aws(&bytes, OffsetDateTime::now_utc())
}
fn parse_aws(bytes: &[u8], now: OffsetDateTime) -> Result<AwsSessionCredentials> {
    if bytes.len() as u64 > MAX_DOCUMENT {
        return Err(fail("oversized AWS response"));
    }
    let doc: CredentialProcessOutput =
        serde_json::from_slice(bytes).map_err(|_| fail("malformed AWS credentials"))?;
    if doc.version != 1 {
        return Err(fail("unsupported AWS response version"));
    }
    let credentials = AwsSessionCredentials {
        access_key_id: doc.access_key_id.clone(),
        secret_access_key: Zeroizing::new(doc.secret_access_key.clone()),
        session_token: Zeroizing::new(doc.session_token.clone()),
        expiration: OffsetDateTime::parse(&doc.expiration, &Rfc3339)
            .map_err(|_| fail("invalid AWS expiry"))?,
    };
    credentials
        .validate(now)
        .map_err(|_| fail("expired or incomplete AWS credentials"))?;
    Ok(credentials)
}

fn subject_token(
    credentials: &AwsSessionCredentials,
    region: &str,
    policy: &GooglePolicy,
    now: OffsetDateTime,
) -> Result<Zeroizing<String>> {
    credentials
        .validate(now)
        .map_err(|_| fail("expired or incomplete AWS credentials"))?;
    keystone_core::config::validate_region(region)?;
    policy.validate()?;
    for field in [
        &credentials.access_key_id,
        &*credentials.secret_access_key,
        &*credentials.session_token,
    ] {
        if !valid_token(field) {
            return Err(fail("malformed AWS credentials"));
        }
    }
    let date = now
        .format(time::macros::format_description!("[year][month][day]"))
        .map_err(|_| fail("invalid clock"))?;
    let amz_date = now
        .format(time::macros::format_description!(
            "[year][month][day]T[hour][minute][second]Z"
        ))
        .map_err(|_| fail("invalid clock"))?;
    let host = format!("sts.{region}.amazonaws.com");
    let query = "Action=GetCallerIdentity&Version=2011-06-15";
    let mut headers = BTreeMap::from([
        ("host", host.clone()),
        ("x-amz-date", amz_date.clone()),
        (
            "x-amz-security-token",
            credentials.session_token.to_string(),
        ),
        ("x-goog-cloud-target-resource", policy.audience.clone()),
    ]);
    let signed_headers = headers.keys().copied().collect::<Vec<_>>().join(";");
    let canonical_headers = Zeroizing::new(
        headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>(),
    );
    let canonical = Zeroizing::new(format!(
        "POST\n/\n{query}\n{}\n{signed_headers}\n{}",
        canonical_headers.as_str(),
        hex::encode(Sha256::digest(b""))
    ));
    let scope = format!("{date}/{region}/sts/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let mut key =
        Zeroizing::new(format!("AWS4{}", credentials.secret_access_key.as_str()).into_bytes());
    for value in [&date, region, "sts", "aws4_request"] {
        key = hmac(&key, value);
    }
    let signature = hex::encode(hmac(&key, &to_sign).as_slice());
    headers.insert("Authorization", format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}", credentials.access_key_id));
    let wire = Zeroizing::new(
        serde_json::to_string(&json!({
            "url": format!("https://{host}/?{query}"), "method": "POST", "body": "",
            "headers": headers.iter().map(|(k,v)| json!({"key":k,"value":v})).collect::<Vec<_>>()
        }))
        .map_err(|_| fail("assertion serialization failed"))?,
    );
    for value in headers.values_mut() {
        value.zeroize();
    }
    Ok(Zeroizing::new(
        url::form_urlencoded::byte_serialize(wire.as_bytes()).collect(),
    ))
}
fn hmac(key: &[u8], value: &str) -> Zeroizing<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

fn mint(
    name: &str,
    policy: &GooglePolicy,
    subject: &str,
    now: i64,
    mut post: impl FnMut(&str, &Value, Option<&str>) -> Result<Value>,
) -> Result<Token> {
    let mut body = json!({
        "audience": policy.audience, "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "subjectTokenType": TOKEN_TYPE, "subjectToken": subject,
        "scope": "https://www.googleapis.com/auth/cloud-platform"
    });
    let response = post("STS", &body, None);
    if let Some(Value::String(s)) = body.get_mut("subjectToken") {
        s.zeroize();
    }
    let mut response = response?;
    let bearer = take_secret(&mut response, "access_token")?;
    if response["token_type"].as_str() != Some("Bearer")
        || response["issued_token_type"].as_str()
            != Some("urn:ietf:params:oauth:token-type:access_token")
        || !matches!(response["expires_in"].as_i64(), Some(1..=3600))
    {
        return Err(fail("malformed STS response"));
    }
    let mut response = post(
        "IAM",
        &json!({"scope": policy.scopes, "lifetime":"3600s"}),
        Some(&bearer),
    )?;
    let token = take_secret(&mut response, "accessToken")?;
    let expiry = response["expireTime"]
        .as_str()
        .ok_or_else(|| fail("missing IAM expiry"))?;
    let expires_at = OffsetDateTime::parse(expiry, &Rfc3339)
        .map_err(|_| fail("invalid IAM expiry"))?
        .unix_timestamp();
    let token = Token {
        version: 1,
        profile: name.into(),
        audience: policy.audience.clone(),
        service_account: policy.service_account.clone(),
        scopes: policy.scopes.clone(),
        access_token: token.to_string(),
        token_type: "Bearer".into(),
        expires_at,
    };
    token.validate(name, policy, now)?;
    Ok(token)
}
fn take_secret(response: &mut Value, field: &str) -> Result<Zeroizing<String>> {
    let Some(Value::String(token)) = response.as_object_mut().and_then(|o| o.remove(field)) else {
        return Err(fail("missing access token"));
    };
    let token = Zeroizing::new(token);
    if !valid_token(&token) {
        return Err(fail("malformed access token"));
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    const NOW: i64 = 1800000000;
    fn policy() -> GooglePolicy {
        GooglePolicy {
            audience: "//iam.googleapis.com/projects/893698030930/locations/global/workloadIdentityPools/keystone-home/providers/aws-mac-mini".into(),
            service_account: "chromebook-control@karulf-home.iam.gserviceaccount.com".into(),
            scopes: vec!["https://www.googleapis.com/auth/admin.directory.device.chromeos".into()],
        }
    }
    fn token(now: i64) -> Token {
        let p = policy();
        Token {
            version: 1,
            profile: "chromebook".into(),
            audience: p.audience,
            service_account: p.service_account,
            scopes: p.scopes,
            access_token: "secret-google-token".into(),
            token_type: "Bearer".into(),
            expires_at: now + 3600,
        }
    }
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            static SERIAL: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "keystone-google-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("token.json")
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn aws(now: i64, id: &str) -> AwsSessionCredentials {
        AwsSessionCredentials {
            access_key_id: id.into(),
            secret_access_key: Zeroizing::new("test-secret".into()),
            session_token: Zeroizing::new("test-session".into()),
            expiration: OffsetDateTime::from_unix_timestamp(now + 900).unwrap(),
        }
    }
    #[test]
    fn exchange_uses_intermediate_cloud_scope_and_final_directory_scope() {
        let mut stages = Vec::new();
        let t = mint("chromebook", &policy(), "encoded-assertion", NOW, |stage, body, bearer| {
            stages.push(stage.to_owned());
            if stage == "STS" {
                assert_eq!(body["subjectToken"], "encoded-assertion");
                assert_eq!(body["subjectTokenType"], TOKEN_TYPE);
                assert_eq!(body["audience"], policy().audience);
                assert_eq!(body["scope"], "https://www.googleapis.com/auth/cloud-platform");
                assert!(bearer.is_none());
                Ok(json!({"access_token":"intermediate-token", "token_type":"Bearer", "issued_token_type":"urn:ietf:params:oauth:token-type:access_token", "expires_in":3600}))
            } else {
                assert_eq!(bearer, Some("intermediate-token"));
                assert_eq!(body, &json!({"scope": policy().scopes, "lifetime":"3600s"}));
                Ok(json!({"accessToken":"final-token", "expireTime":OffsetDateTime::from_unix_timestamp(NOW+3600).unwrap().format(&Rfc3339).unwrap()}))
            }
        }).unwrap();
        assert_eq!(stages, ["STS", "IAM"]);
        assert_eq!(t.access_token, "final-token");
        assert!(!format!("{t:?}").contains("final-token"));
    }
    #[test]
    fn policy_and_expiry_mismatches_fail_closed() {
        let t = token(NOW);
        t.validate("chromebook", &policy(), NOW).unwrap();
        assert!(t.validate("other", &policy(), NOW).is_err());
        for field in ["audience", "service_account", "scope"] {
            let mut p = policy();
            match field {
                "audience" => p.audience.push('x'),
                "scope" => p.scopes.push("other".into()),
                _ => p.service_account.insert(0, 'x'),
            }
            assert!(t.validate("chromebook", &p, NOW).is_err());
        }
        assert!(t.validate("chromebook", &policy(), NOW + 3600).is_err());
        let mut p = policy();
        p.audience = "https://attacker.example".into();
        assert!(p.validate().is_err());
        let mut p = policy();
        p.service_account = "user@example.com".into();
        assert!(p.validate().is_err());
        let mut p = policy();
        p.scopes = vec!["scope with whitespace".into()];
        assert!(p.validate().is_err());
    }
    #[test]
    fn renewed_assertions_use_current_aws_credentials_and_time() {
        let a = subject_token(
            &aws(NOW, "first"),
            "us-east-2",
            &policy(),
            OffsetDateTime::from_unix_timestamp(NOW).unwrap(),
        )
        .unwrap();
        let b = subject_token(
            &aws(NOW + 3600, "second"),
            "us-east-2",
            &policy(),
            OffsetDateTime::from_unix_timestamp(NOW + 3600).unwrap(),
        )
        .unwrap();
        assert_ne!(*a, *b);
        let decoded = url::form_urlencoded::parse(a.as_bytes())
            .next()
            .unwrap()
            .0
            .into_owned();
        let request: Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(request["method"], "POST");
        assert_eq!(
            request["url"],
            "https://sts.us-east-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
        );
        let headers: BTreeMap<_, _> = request["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| (h["key"].as_str().unwrap(), h["value"].as_str().unwrap()))
            .collect();
        assert_eq!(headers["x-goog-cloud-target-resource"], policy().audience);
        assert!(headers["Authorization"]
            .contains("host;x-amz-date;x-amz-security-token;x-goog-cloud-target-resource"));
        assert!(headers["Authorization"].contains("Credential=first/"));
        // Independently generated with botocore SigV4Auth using these public test credentials.
        assert!(headers["Authorization"].ends_with(
            "Signature=f71f358d4e16bf1880c0e16c27477923c1b8afdbb6483fff5733336bcfda4ec6"
        ));
        assert!(subject_token(
            &aws(NOW, "first"),
            "us-east-2",
            &policy(),
            OffsetDateTime::from_unix_timestamp(NOW + 900).unwrap()
        )
        .is_err());
    }
    #[test]
    fn cache_refreshes_across_google_expiry_and_restart() {
        let dir = Temp::new();
        for now in [NOW, NOW + 3601, NOW + 7202] {
            let t = cached_or_refresh(
                &dir.path(),
                "binding",
                "chromebook",
                &policy(),
                || now,
                || Ok(token(now)),
            )
            .unwrap();
            assert_eq!(t.expires_at, now + 3600);
            cached_or_refresh(
                &dir.path(),
                "binding",
                "chromebook",
                &policy(),
                || now + 1,
                || panic!("fresh cache must survive a new invocation"),
            )
            .unwrap();
        }
        // A trust/key/config change invalidates an otherwise fresh cache.
        cached_or_refresh(
            &dir.path(),
            "changed-key",
            "chromebook",
            &policy(),
            || NOW + 7203,
            || Ok(token(NOW + 7203)),
        )
        .unwrap();
    }
    #[test]
    fn concurrent_process_style_callers_coalesce_refresh() {
        let dir = Temp::new();
        let count = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..12 {
            let path = dir.path();
            let lock_path = dir.0.join("lock");
            let count = count.clone();
            threads.push(std::thread::spawn(move || {
                let file = open_private(&lock_path, true).unwrap();
                lock(&file, Instant::now() + Duration::from_secs(2)).unwrap();
                cached_or_refresh(
                    &path,
                    "binding",
                    "chromebook",
                    &policy(),
                    || NOW,
                    || {
                        count.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(40));
                        Ok(token(NOW))
                    },
                )
                .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn failures_back_off_and_recover_without_restart() {
        for class in [
            "STS HTTP 403",
            "STS HTTP 429",
            "IAM HTTP 503",
            "IAM HTTP 403",
            "AWS credential acquisition failed",
        ] {
            let dir = Temp::new();
            let e = cached_or_refresh(
                &dir.path(),
                "binding",
                "chromebook",
                &policy(),
                || NOW,
                || Err(fail(class)),
            )
            .unwrap_err();
            assert!(e.to_string().contains(class));
            assert!(cached_or_refresh(
                &dir.path(),
                "binding",
                "chromebook",
                &policy(),
                || NOW + 1,
                || panic!("backoff must suppress refresh")
            )
            .is_err());
            cached_or_refresh(
                &dir.path(),
                "binding",
                "chromebook",
                &policy(),
                || NOW + 6,
                || Ok(token(NOW + 6)),
            )
            .unwrap();
        }
    }
    #[test]
    fn malformed_and_unsafe_files_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = Temp::new();
        assert!(read_file(&dir.path()).is_err());
        write_atomic(&dir.path(), b"not-json-secret").unwrap();
        let e = cached_or_refresh(
            &dir.path(),
            "binding",
            "chromebook",
            &policy(),
            || NOW,
            || panic!("malformed cache must fail closed"),
        )
        .unwrap_err();
        assert!(!e.to_string().contains("not-json-secret"));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file(&dir.path()).is_err());
        let link = dir.0.join("link");
        symlink(dir.path(), &link).unwrap();
        assert!(read_file(&link).is_err());
        let nested = dir.0.join("nested");
        symlink(&dir.0, &nested).unwrap();
        assert!(open_private(&nested.join("new"), true).is_err());
    }
    #[test]
    fn missing_and_malformed_remote_credentials_are_redacted() {
        for bad in [
            json!({}),
            json!({"access_token":"secret", "token_type":"id_token"}),
            json!({"access_token":"secret", "token_type":"Bearer", "issued_token_type":"urn:ietf:params:oauth:token-type:access_token", "expires_in":0}),
        ] {
            let e = mint(
                "chromebook",
                &policy(),
                "secret-assertion",
                NOW,
                |_, _, _| Ok(bad.clone()),
            )
            .unwrap_err();
            assert!(!e.to_string().contains("secret"));
        }
        for bad in [b"{secret".as_slice(), b"{}"] {
            let e = parse_aws(bad, OffsetDateTime::from_unix_timestamp(NOW).unwrap()).unwrap_err();
            assert!(!e.to_string().contains("secret"));
        }
    }
    #[test]
    fn malformed_or_expired_iam_tokens_never_escape() {
        for response in [
            json!({}),
            json!({"accessToken":"secret", "expireTime":"invalid-secret"}),
            json!({"accessToken":"secret", "expireTime":OffsetDateTime::from_unix_timestamp(NOW).unwrap().format(&Rfc3339).unwrap()}),
        ] {
            let result = mint("chromebook", &policy(), "assertion", NOW, |stage, _, _| {
                if stage == "STS" {
                    Ok(
                        json!({"access_token":"intermediate", "token_type":"Bearer", "issued_token_type":"urn:ietf:params:oauth:token-type:access_token", "expires_in":3600}),
                    )
                } else {
                    Ok(response.clone())
                }
            });
            assert!(!result.unwrap_err().to_string().contains("secret"));
        }
        let dir = Temp::new();
        assert!(cached_or_refresh(
            &dir.path(),
            "binding",
            "chromebook",
            &policy(),
            || NOW,
            || {
                let mut t = token(NOW);
                t.expires_at = NOW + 10;
                Ok(t)
            }
        )
        .is_err());
    }

    #[test]
    fn google_policy_survives_config_updates_and_rejects_unknown_fields() {
        let mut config = Config::default();
        let mut profile = keystone_core::config::Profile::new("us-east-2");
        profile.google = Some(policy());
        config.profiles.insert("chromebook".into(), profile);
        let text = config.render().unwrap();
        assert_eq!(
            Config::parse(&text)
                .unwrap()
                .profile("chromebook")
                .unwrap()
                .google,
            Some(policy())
        );
        assert!(Config::parse(&text.replace(
            "[profiles.chromebook.google]",
            "[profiles.chromebook.google]\nsubject = 'user@example.com'"
        ))
        .is_err());
    }

    #[test]
    fn nonregular_private_files_fail_without_waiting_for_a_writer() {
        let dir = Temp::new();
        assert!(std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(dir.path())
            .status()
            .unwrap()
            .success());
        assert!(read_file(&dir.path()).is_err());
        assert!(open_private(&dir.path(), true).is_err());
        assert!(read_file(&dir.0).is_err());
    }

    #[test]
    fn lock_wait_is_bounded() {
        let dir = Temp::new();
        let path = dir.0.join("lock");
        let first = open_private(&path, true).unwrap();
        lock(&first, Instant::now() + Duration::from_secs(1)).unwrap();
        let second = open_private(&path, true).unwrap();
        assert!(lock(&second, Instant::now() + Duration::from_millis(30)).is_err());
    }
}
