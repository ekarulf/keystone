//! `keystone bootstrap` — identity, one-shot CA, and device certificate.
//!
//! The design's sequence, in order:
//!
//! 1. Generate the hardware P-256 signing key.
//! 2. Generate a temporary software P-256 CA key.
//! 3. Create a self-signed CA certificate.
//! 4. Construct the Keystone device certificate.
//! 5. Sign the device certificate with the CA.
//! 6. Verify the leaf certificate and chain.
//! 7. Verify the leaf public key matches the hardware key.
//! 8. Persist only public certificate material.
//! 9. Generate the CDK project.
//! 10. Discard the CA private scalar.
//! 11. Exit the short-lived bootstrap process.
//!
//! Steps 2 through 7 and 10 happen inside `keystone_pki::ephemeral_ca::issue`,
//! which never returns the CA key; this module never sees it. Steps 6 and 7 run
//! before anything is written, so a bootstrap that produced something Keystone
//! would later reject leaves no state behind.
//!
//! The design writes step 10 as "zeroize", which `ephemeral_ca` cannot do: *ring*
//! owns the scalar and exposes no way to overwrite it. The key is made
//! unreachable and the process is short-lived, which is the mitigation actually in
//! place. `EphemeralCaKey`'s documentation is the authority on the difference.

use std::path::{Path, PathBuf};

use crate::backend::{DeviceKey, KeyPolicy};
use keystone_core::config::{
    validate_profile_name, validate_region, validate_role_session_name, IssuerMetadata, Profile,
};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use keystone_core::signer::KeystoneSigningIdentity as _;
use keystone_core::store::write_atomic;
use keystone_pki::{DeviceCertificateSpec, EphemeralCaSpec};
use time::OffsetDateTime;

use crate::cli::{BootstrapArgs, CdkPlanArgs};
use crate::context::{parse_validity, Context};

pub fn run(context: &Context, args: &BootstrapArgs) -> Result<()> {
    validate_profile_name(&args.profile)?;
    validate_region(&args.region)?;
    if let Some(session_name) = &args.role_session_name {
        validate_role_session_name(session_name)?;
    }
    let leaf_validity = parse_validity(&args.leaf_validity)?;
    let ca_validity = parse_validity(&args.ca_validity)?;
    if ca_validity < leaf_validity {
        return Err(KeystoneError::InvalidConfiguration(
            "--ca-validity must be at least as long as --leaf-validity: a device certificate \
             outliving its CA cannot be validated"
                .to_string(),
        ));
    }

    let mut config = context.load_config()?;
    if let Some(existing) = config.profiles.get(&args.profile) {
        if existing.key_id.is_some() && !args.force {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "profile {:?} already has an identity. Pass --force to replace it — the existing \
                 certificate and trust anchor stop working — or run `keystone rotate` for the \
                 safe sequence that deploys the new anchor first.",
                args.profile
            )));
        }
    }

    let now = context.now_checked()?;

    // Step 1.
    let key_id = KeyId::generate();
    let policy = KeyPolicy::default();
    context.detail(format!(
        "generating a {} P-256 signing key ({})",
        crate::backend::KEY_STORE,
        policy.describe()
    ));
    let generated = DeviceKey::generate(key_id.clone(), policy, now)?;
    let public_key = generated.identity.public_key_sec1()?;

    // Steps 2 to 7, and 10.
    let device = DeviceCertificateSpec::new(&args.device_name, key_id.clone(), now)
        .with_organization(args.organization.clone())
        .with_validity(now, now + leaf_validity);
    let ca = EphemeralCaSpec::new(key_id.clone(), now).with_validity(now, now + ca_validity);
    context.detail("issuing a device certificate from a one-shot CA");
    let issued = keystone_pki::ephemeral_ca::issue(&public_key, &device, &ca, now)?;

    // A last independent check that the enclave can sign against what was just
    // issued: `issue` verified the public keys match, this verifies the private
    // half agrees.
    let probe = generated
        .identity
        .sign_message_ecdsa_sha256(b"keystone bootstrap signing probe")?;
    keystone_pki::verify_device_signature(
        &issued.device_certificate,
        b"keystone bootstrap signing probe",
        &probe,
    )?;

    // Step 8. Public material only — there is no CA key to persist, by
    // construction: `issue` dropped it before returning.
    let device_fingerprint = issued.device_fingerprint();
    context.store.save_identity(&generated.metadata)?;
    context.store.save_certificates(
        &device_fingerprint,
        issued.device_certificate.der(),
        issued.ca_certificate.der(),
    )?;

    let profile = config
        .profiles
        .entry(args.profile.clone())
        .or_insert_with(|| Profile::new(&args.region));
    profile.region = args.region.clone();
    profile.key_id = Some(key_id.clone());
    profile.key_accessibility = policy.accessibility();
    profile.certificate_fingerprint_sha256 = Some(device_fingerprint.clone());
    profile.ca_fingerprint_sha256 = Some(issued.ca_fingerprint());
    profile.issuer = Some(IssuerMetadata::ephemeral(
        issued.device_certificate.not_after,
    ));
    // Default the session name to the device name, which is the point of asking
    // for a device name at all: it is what appears after the role in the assumed
    // role ARN and in every CloudTrail event.
    //
    // Sending nothing is not neutral. Roles Anywhere then derives a session name
    // itself — the SHA-256 of the certificate's public-key point, truncated to 20
    // bytes — so CloudTrail reads `assumed-role/KeystoneLaptop/1fb91081daf1...`,
    // which identifies the device only to someone willing to hash a public key.
    // The generated profile sets `acceptRoleSessionName: true` precisely so this
    // name is honored.
    profile.role_session_name =
        default_role_session_name(args.role_session_name.as_deref(), &args.device_name);
    let profile = profile.clone();
    context.save_config(&config)?;

    // Step 9.
    let mut written_cdk: Option<PathBuf> = None;
    if let Some(output) = &args.generate_cdk {
        let plan_args = CdkPlanArgs {
            profile: args.profile.clone(),
            stack_name: None,
            role_name: None,
            trust_anchor_name: None,
            roles_anywhere_profile_name: None,
            existing_trust_anchor_arn: None,
            existing_role_arn: None,
            policy: None,
            managed_policy_arn: Vec::new(),
            duration_seconds: None,
        };
        let plan = crate::plan::build(context, &plan_args, &profile)?;
        let project = keystone_infra::GeneratedProject::render(&plan, now)?;
        let report = project.write(output, args.force)?;
        crate::commands::infra::report_written(context, &report);
        written_cdk = Some(output.clone());
    }

    if let Some(output) = &args.output {
        write_bootstrap_artifacts(context, output, args, &issued, &key_id, &profile, now)?;
    }

    context.note("Bootstrap complete. No CA private key was written to disk.");
    context.note("");
    context.note(format!("Profile: {}", args.profile));
    context.note(format!("Key ID: {key_id}"));
    context.note(format!("Device URI SAN: {}", key_id.device_san_uri()));
    context.note(format!(
        "Certificate expires: {}",
        keystone_core::time::format_rfc3339(issued.device_certificate.not_after)
    ));
    context.note(format!(
        "CA fingerprint: {}",
        issued.ca_fingerprint().display_short()
    ));
    context.note("");
    context.note("This certificate cannot be renewed: the CA key no longer exists.");
    context.note(format!(
        "When it approaches expiry, run `keystone rotate --profile {}`.",
        args.profile
    ));
    context.note("");
    context.note("Next:");
    match &written_cdk {
        Some(dir) => {
            context.note(format!("    cd {} && npm install", dir.display()));
            context.note("    npx cdk deploy --outputs-file cdk-outputs.json");
            context.note(format!(
                "    keystone infra cdk sync-profile --profile {} --outputs {}",
                args.profile,
                dir.join("cdk-outputs.json").display()
            ));
        }
        None => {
            context.note(format!(
                "    keystone infra cdk init --profile {} --output ./keystone-infra",
                args.profile
            ));
        }
    }
    context.note(format!("    keystone test --profile {}", args.profile));
    Ok(())
}

/// Write the public bootstrap bundle the design describes.
///
/// Deliberately absent: `ca-private-key.pem`. There is nothing to write it from.
fn write_bootstrap_artifacts(
    context: &Context,
    output: &Path,
    args: &BootstrapArgs,
    issued: &keystone_pki::EphemeralCaOutput,
    key_id: &KeyId,
    profile: &Profile,
    now: OffsetDateTime,
) -> Result<()> {
    write_atomic(
        &output.join("ca-certificate.pem"),
        issued.ca_certificate.to_pem().as_bytes(),
    )?;
    write_atomic(
        &output.join("device-certificate.pem"),
        issued.device_certificate.to_pem().as_bytes(),
    )?;
    write_atomic(
        &output.join("device-chain.pem"),
        issued.chain_pem().as_bytes(),
    )?;

    let manifest = serde_json::json!({
        "version": 1,
        "generator": concat!("keystone ", env!("CARGO_PKG_VERSION")),
        "generated_at": keystone_core::time::format_rfc3339(now),
        "profile": args.profile,
        "region": args.region,
        "key_id": key_id.as_str(),
        "device_san_uri": key_id.device_san_uri(),
        "device_name": args.device_name,
        "ca_mode": args.ca_mode,
        "ca_private_key_persisted": false,
        "certificate": {
            "subject": issued.device_certificate.subject,
            "issuer": issued.device_certificate.issuer,
            "serial_decimal": issued.device_certificate.serial_decimal,
            "not_before": keystone_core::time::format_rfc3339(issued.device_certificate.not_before),
            "not_after": keystone_core::time::format_rfc3339(issued.device_certificate.not_after),
            "fingerprint_sha256": issued.device_fingerprint().as_str(),
        },
        "ca_certificate": {
            "subject": issued.ca_certificate.subject,
            "not_after": keystone_core::time::format_rfc3339(issued.ca_certificate.not_after),
            "fingerprint_sha256": issued.ca_fingerprint().as_str(),
        },
        "renewable": false,
        "trust_anchor_rotation_required": true,
    });
    let manifest = serde_json::to_string_pretty(&manifest)
        .map_err(|error| KeystoneError::Other(format!("cannot render the manifest: {error}")))?;
    write_atomic(
        &output.join("bootstrap-manifest.json"),
        format!("{manifest}\n").as_bytes(),
    )?;

    // A single-profile copy of the configuration, so the bundle records what was
    // configured without exposing other profiles.
    let mut single = keystone_core::config::Config::default();
    single
        .profiles
        .insert(args.profile.clone(), profile.clone());
    write_atomic(
        &output.join("keystone-profile.toml"),
        single.render()?.as_bytes(),
    )?;

    context.note(format!("Wrote bootstrap artifacts to {}", output.display()));
    Ok(())
}

/// The session name to record, given an explicit choice and the device name.
///
/// A device name is a certificate CN, so it may hold characters IAM rejects in a
/// session name. An unusable default is dropped rather than failing the whole
/// bootstrap over a cosmetic field.
fn default_role_session_name(explicit: Option<&str>, device_name: &str) -> Option<String> {
    match explicit {
        Some(session_name) => Some(session_name.to_string()),
        None => validate_role_session_name(device_name)
            .ok()
            .map(|()| device_name.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_name_becomes_the_session_name_by_default() {
        // Without this, Roles Anywhere names the session itself: the SHA-256 of
        // the certificate's public-key point truncated to 20 bytes. CloudTrail
        // then shows `assumed-role/KeystoneLaptop/1fb91081daf1...`, which is
        // exactly the identification the device name is collected to provide.
        assert_eq!(
            default_role_session_name(None, "example-laptop").as_deref(),
            Some("example-laptop")
        );
    }

    #[test]
    fn an_explicit_session_name_wins() {
        assert_eq!(
            default_role_session_name(Some("build-agent"), "example-laptop").as_deref(),
            Some("build-agent")
        );
    }

    #[test]
    fn a_device_name_iam_would_reject_is_dropped_rather_than_failing_bootstrap() {
        // A CN may contain spaces; a session name may not. Sending it would make
        // CreateSession fail for every refresh, which is far worse than falling
        // back to the name Roles Anywhere derives.
        assert_eq!(default_role_session_name(None, "My Laptop Pro"), None);
        assert_eq!(default_role_session_name(None, "x"), None);
        assert_eq!(default_role_session_name(None, &"n".repeat(65)), None);
    }
}
