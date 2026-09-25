//! Issue a service JWT using the profile's existing hardware identity.

use keystone_core::error::{KeystoneError, Result};
use keystone_pki::token::{issue_es256_token, TokenClaims};
use url::Url;

use crate::cli::TokenArgs;
use crate::context::{print_line, Context};

pub fn run(context: &Context, args: &TokenArgs) -> Result<()> {
    validate_https_url(&args.issuer, "issuer")?;
    validate_https_url(&args.audience, "audience")?;
    let profile = context.load_profile(&args.profile)?;
    let key = crate::identity::load_key(&context.store, &args.profile, &profile)?;
    let now = context.now_checked()?;
    let token = issue_es256_token(
        &key,
        &TokenClaims {
            issuer: &args.issuer,
            audience: &args.audience,
            issued_at: now,
            expires_at: now + time::Duration::minutes(args.ttl_minutes),
        },
    )?;
    print_line(&token)
}

fn validate_https_url(value: &str, name: &str) -> Result<()> {
    if !value.starts_with("https://")
        || value.contains('\\')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return Err(invalid_url(name));
    }
    let url = Url::parse(value).map_err(|_| invalid_url(name))?;
    // `Url::username()` is empty for `https://@host`, which still contains
    // URL userinfo. Reject it along with non-empty credentials.
    let authority = value["https://".len()..]
        .split(['/', '?', '#'])
        .next()
        .expect("split always returns one element");
    if url.scheme() != "https"
        || url.host().is_none()
        || authority.is_empty()
        || authority.contains('@')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_url(name));
    }
    Ok(())
}

fn invalid_url(name: &str) -> KeystoneError {
    KeystoneError::InvalidConfiguration(format!(
        "{name} must be an absolute HTTPS URL without credentials or a fragment"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_preserves_supported_https_values() {
        for value in ["https://auth.example.com", "https://api.example.com/v1/"] {
            validate_https_url(value, "issuer").unwrap();
        }
        for value in [
            "http://auth.example.com",
            "https:example.com",
            "https:/example.com",
            "https:///example.com",
            "https://\\example.com",
            "not-a-url",
            "https://user:pass@example.com",
            "https://@example.com",
            "https://example.com/#fragment",
        ] {
            assert!(validate_https_url(value, "issuer").is_err(), "{value}");
        }
    }
}
