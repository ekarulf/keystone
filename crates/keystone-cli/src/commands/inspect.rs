//! `keystone inspect` — what Keystone knows about a profile.
//!
//! "No secret data should be printed." Everything below is either public
//! certificate material, a fingerprint, an ARN, or local configuration. The
//! opaque hardware key reference is deliberately not among them.
//!
//! This is also the one diagnostic command that must work on a half-configured
//! profile, so each section degrades to a line saying what is missing rather than
//! failing the command.

use keystone_core::config::Profile;
use keystone_core::error::Result;
use keystone_pki::ParsedCertificate;

use crate::cli::ProfileArgs;
use crate::context::{print_line, Context};

pub fn run(context: &Context, args: &ProfileArgs) -> Result<()> {
    let profile = context.load_profile(&args.profile)?;
    let now = context.now();

    let mut out = Vec::new();
    out.push(format!("Profile: {}", args.profile));
    out.push(format!("Key backend: {}", crate::backend::KEY_STORE));
    out.push("Key algorithm: P-256 ECDSA".to_string());

    match &profile.key_id {
        Some(key_id) => {
            out.push(format!("Key ID: {key_id}"));
            match context.store.load_identity(key_id) {
                Ok(metadata) => {
                    out.push(format!(
                        "Public-key fingerprint: {}",
                        metadata.public_key_fingerprint_sha256.display_short()
                    ));
                    out.push(format!(
                        "Key created: {}",
                        keystone_core::time::format_rfc3339(metadata.created_at)
                    ));
                }
                Err(error) => out.push(format!("Public-key fingerprint: unavailable ({error})")),
            }
            out.push(format!(
                "Key accessibility: {}",
                profile.key_accessibility.describe()
            ));
            out.push(format!("Device URI SAN: {}", key_id.device_san_uri()));
        }
        None => out.push("Key ID: none — run `keystone init` or `keystone bootstrap`".to_string()),
    }

    out.push(String::new());
    match certificate(context, &profile) {
        Some(Ok((leaf, ca))) => describe_certificates(&mut out, &leaf, &ca, now),
        Some(Err(error)) => out.push(format!("Certificate: unreadable ({error})")),
        None => out.push("Certificate: none installed".to_string()),
    }

    out.push(String::new());
    match &profile.issuer {
        Some(issuer) => {
            out.push(format!(
                "Issuer mode: {}",
                match issuer.mode {
                    keystone_core::config::IssuerMode::EphemeralCa => "ephemeral-ca",
                    keystone_core::config::IssuerMode::ExternalCa => "external-ca",
                }
            ));
            out.push(format!(
                "Renewable: {}",
                if issuer.renewable { "yes" } else { "no" }
            ));
            out.push(format!(
                "Trust-anchor rotation required: {}",
                if issuer.trust_anchor_rotation_required {
                    "yes"
                } else {
                    "no"
                }
            ));
        }
        None => out.push("Issuer mode: unknown".to_string()),
    }

    out.push(String::new());
    out.push(format!("AWS region: {}", profile.region));
    out.push(format!("Trust-anchor ARN: {}", profile.trust_anchor_arn));
    out.push(format!(
        "Roles Anywhere profile ARN: {}",
        profile.roles_anywhere_profile_arn
    ));
    out.push(format!("Role ARN: {}", profile.role_arn));
    out.push(format!("Session duration: {}s", profile.duration_seconds));
    if let Some(session_name) = &profile.role_session_name {
        out.push(format!("Role session name: {session_name}"));
    }

    for line in out {
        print_line(&line)?;
    }

    // Warnings go to standard error, so `keystone inspect > report.txt` captures
    // the report and the operator still sees the warning.
    if let Some(Ok((leaf, _))) = certificate(context, &profile) {
        if let Some(warning) =
            keystone_pki::validate::expiry_warning(&leaf, now, time::Duration::days(90))
        {
            context.note("");
            context.note(format!("warning: {warning}"));
            if profile.issuer.as_ref().is_some_and(|i| !i.renewable) {
                context.note(
                    "This certificate was issued by a destroyed ephemeral CA and cannot be \
                     renewed. Run:",
                );
                context.note(format!("    keystone rotate --profile {}", args.profile));
            }
        }
    }
    Ok(())
}

/// Load the stored pair, distinguishing "none recorded" from "unreadable".
fn certificate(
    context: &Context,
    profile: &Profile,
) -> Option<Result<(ParsedCertificate, ParsedCertificate)>> {
    let fingerprint = profile.certificate_fingerprint_sha256.as_ref()?;
    Some(
        context
            .store
            .load_certificates(fingerprint)
            .and_then(|(leaf, ca)| {
                Ok((
                    ParsedCertificate::from_der(&leaf)?,
                    ParsedCertificate::from_der(&ca)?,
                ))
            }),
    )
}

fn describe_certificates(
    out: &mut Vec<String>,
    leaf: &ParsedCertificate,
    ca: &ParsedCertificate,
    now: time::OffsetDateTime,
) {
    out.push(format!("Certificate subject: {}", leaf.subject));
    out.push(format!("Certificate issuer: {}", leaf.issuer));
    out.push(format!("Certificate serial: {}", leaf.serial_decimal));
    out.push(format!(
        "Certificate expires: {}",
        keystone_core::time::format_rfc3339(leaf.not_after)
    ));
    out.push(format!(
        "Certificate remaining: {}",
        keystone_core::time::describe_duration_days(leaf.remaining(now))
    ));
    for san in &leaf.uri_sans {
        out.push(format!("Certificate SAN: {san}"));
    }
    out.push(format!(
        "Certificate fingerprint: {}",
        leaf.fingerprint().display_short()
    ));
    out.push(format!("CA subject: {}", ca.subject));
    out.push(format!(
        "CA expires: {}",
        keystone_core::time::format_rfc3339(ca.not_after)
    ));
    out.push(format!(
        "CA fingerprint: {}",
        ca.fingerprint().display_short()
    ));
}
