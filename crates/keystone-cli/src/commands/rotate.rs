//! `keystone rotate` — replace the identity, certificate, and trust anchor.
//!
//! An identity issued by a destroyed CA cannot be renewed, so rotation means a
//! new key, a new one-shot CA, a new device certificate, and a second trust
//! anchor. The design's safe sequence is:
//!
//! 1. Generate a new hardware key.
//! 2. Generate a new ephemeral CA.
//! 3. Issue a new device certificate.
//! 4. Deploy a second trust anchor.
//! 5. Add or deploy the new Roles Anywhere profile.
//! 6. Test `CreateSession`.
//! 7. Atomically switch the local Keystone profile.
//! 8. Disable the old trust anchor.
//! 9. Retain it briefly for rollback.
//! 10. Delete the old trust anchor and local key reference.
//!
//! Steps 4 through 6 and 8 through 10 are the operator's, and steps 4 and 5 are
//! deliberately not automated. So this command splits at the boundary: a plain
//! run performs 1 through 3 and records what it prepared; `--activate` performs
//! step 7 against that record. Splitting it this way is what makes the profile
//! switch a separate, reversible decision from generating new key material —
//! and it means re-running `--activate` does not mint yet another key.

use std::path::{Path, PathBuf};

use crate::backend::{DeviceKey, KeyPolicy};
use keystone_core::config::{IssuerMetadata, Profile};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::{KeyId, Sha256Fingerprint};
use keystone_core::signer::KeystoneSigningIdentity as _;
use keystone_core::store::write_atomic;
use keystone_pki::{DeviceCertificateSpec, EphemeralCaSpec};
use time::OffsetDateTime;

use crate::cli::{CdkPlanArgs, RotateArgs};
use crate::context::{parse_validity, Context};

/// What a prepared-but-not-activated rotation recorded.
struct Pending {
    key_id: KeyId,
    certificate_fingerprint: Sha256Fingerprint,
    ca_fingerprint: Sha256Fingerprint,
    certificate_expires_at: OffsetDateTime,
    prepared_at: OffsetDateTime,
    /// Where `--generate-cdk` wrote the project, so `--activate` can name the
    /// real `cdk-outputs.json` rather than a guess at where it might be.
    cdk_output: Option<PathBuf>,
}

pub fn run(context: &Context, args: &RotateArgs) -> Result<()> {
    let profile = context.load_profile(&args.profile)?;
    let path = pending_path(context, &args.profile);

    // An existing record takes precedence: the whole point of the two-step flow is
    // that `--activate` finishes what a previous run prepared.
    if let Some(pending) = read_pending(&path)? {
        if args.activate {
            return activate(context, args, &profile, pending, &path);
        }
        return Err(KeystoneError::InvalidConfiguration(format!(
            "a rotation for profile {:?} is already prepared: key {}, certificate {}, prepared \
             {}. Deploy its trust anchor and then run `keystone rotate --profile {} --activate`, \
             or delete {} to start over.",
            args.profile,
            pending.key_id,
            pending.certificate_fingerprint.display_short(),
            keystone_core::time::format_rfc3339(pending.prepared_at),
            args.profile,
            path.display()
        )));
    }

    let pending = prepare(context, args, &profile, &path)?;
    if args.activate {
        // Activating in the same run skips steps 4 through 6, so say so.
        context.note("");
        context.note(
            "warning: activating immediately. The new trust anchor is not deployed yet, so \
             credentials will fail until it is.",
        );
        return activate(context, args, &profile, pending, &path);
    }
    Ok(())
}

/// Steps 1 to 3, plus the CDK project for the second trust anchor.
fn prepare(
    context: &Context,
    args: &RotateArgs,
    profile: &Profile,
    path: &Path,
) -> Result<Pending> {
    let previous_key_id = context.require_key_id(&args.profile, profile)?;
    let leaf_validity = parse_validity(&args.leaf_validity)?;
    let ca_validity = parse_validity(&args.ca_validity)?;
    if ca_validity < leaf_validity {
        return Err(KeystoneError::InvalidConfiguration(
            "--ca-validity must be at least as long as --leaf-validity".to_string(),
        ));
    }
    let now = context.now_checked()?;

    let device_name = match &args.device_name {
        Some(name) => name.clone(),
        // Carry the existing certificate's common name forward, so a rotation does
        // not silently rename the device in CloudTrail and in the CA's records.
        None => existing_device_name(context, profile)
            .unwrap_or_else(|| format!("keystone-{}", previous_key_id.short())),
    };

    let key_id = KeyId::generate();
    let policy = KeyPolicy::new(profile.key_accessibility);
    context.detail(format!(
        "generating a new {} key ({})",
        crate::backend::KEY_STORE,
        policy.describe()
    ));
    let generated = DeviceKey::generate(key_id.clone(), policy, now)?;
    let public_key = generated.identity.public_key_sec1()?;

    let device = DeviceCertificateSpec::new(&device_name, key_id.clone(), now)
        .with_organization(args.organization.clone())
        .with_validity(now, now + leaf_validity);
    let ca = EphemeralCaSpec::new(key_id.clone(), now).with_validity(now, now + ca_validity);
    let issued = keystone_pki::ephemeral_ca::issue(&public_key, &device, &ca, now)?;

    let probe = generated
        .identity
        .sign_message_ecdsa_sha256(b"keystone rotate signing probe")?;
    keystone_pki::verify_device_signature(
        &issued.device_certificate,
        b"keystone rotate signing probe",
        &probe,
    )?;

    // The new material lives alongside the old: the profile still points at the
    // old key, so nothing in use is disturbed. This is what makes the rollback
    // window in step 9 possible.
    let certificate_fingerprint = issued.device_fingerprint();
    context.store.save_identity(&generated.metadata)?;
    context.store.save_certificates(
        &certificate_fingerprint,
        issued.device_certificate.der(),
        issued.ca_certificate.der(),
    )?;

    let pending = Pending {
        key_id: key_id.clone(),
        certificate_fingerprint: certificate_fingerprint.clone(),
        ca_fingerprint: issued.ca_fingerprint(),
        certificate_expires_at: issued.device_certificate.not_after,
        prepared_at: now,
        cdk_output: args.generate_cdk.clone(),
    };
    // Recorded before the project is rendered: the key exists from here on, and a
    // record naming it is what lets a re-run resume instead of minting another.
    write_pending(path, &pending, &previous_key_id)?;

    // The generated stack has to describe the *new* identity, so the plan is built
    // against a copy of the profile carrying the new key and certificate, not the
    // live profile.
    let mut rotated = profile.clone();
    rotated.key_id = Some(key_id.clone());
    rotated.certificate_fingerprint_sha256 = Some(certificate_fingerprint);
    rotated.ca_fingerprint_sha256 = Some(pending.ca_fingerprint.clone());
    rotated.issuer = Some(IssuerMetadata::ephemeral(pending.certificate_expires_at));

    if let Some(output) = &args.generate_cdk {
        let plan_args = CdkPlanArgs {
            profile: args.profile.clone(),
            // A distinct stack name: deploying the rotation over the existing
            // stack would replace the trust anchor that is still in use, which is
            // the opposite of a second anchor.
            stack_name: Some(rotation_stack_name(&args.profile, &key_id)),
            role_name: None,
            trust_anchor_name: Some(format!("keystone-{}-{}", args.profile, key_id.short())),
            roles_anywhere_profile_name: Some(format!(
                "keystone-{}-{}",
                args.profile,
                key_id.short()
            )),
            existing_trust_anchor_arn: None,
            // Reuse the role that already exists: rotation replaces the identity,
            // not the permissions.
            existing_role_arn: (profile.role_arn != keystone_core::config::PLACEHOLDER)
                .then(|| profile.role_arn.clone()),
            policy: None,
            managed_policy_arn: Vec::new(),
            duration_seconds: None,
        };
        let plan = crate::plan::build(context, &plan_args, &rotated)?;
        let project = keystone_infra::GeneratedProject::render(&plan, now)?;
        let report = project.write(output, false)?;
        crate::commands::infra::report_written(context, &report);
    }

    context.note("Prepared a new identity. The profile still uses the old one.");
    context.note("");
    context.note(format!("New key ID: {key_id}"));
    context.note(format!("New device URI SAN: {}", key_id.device_san_uri()));
    context.note(format!(
        "New certificate expires: {}",
        keystone_core::time::format_rfc3339(pending.certificate_expires_at)
    ));
    context.note(format!("Previous key ID: {previous_key_id}"));
    context.note("");
    context.note("Next, deploy the second trust anchor, then switch:");
    match &pending.cdk_output {
        Some(dir) => {
            context.note(format!("    cd {} && npm install", dir.display()));
            context.note("    npx cdk deploy --outputs-file cdk-outputs.json");
        }
        None => context.note(format!(
            "    keystone rotate --profile {} --generate-cdk ./keystone-rotation",
            args.profile
        )),
    }
    context.note(format!(
        "    keystone rotate --profile {} --activate",
        args.profile
    ));
    if let Some(dir) = &pending.cdk_output {
        context.note(format!(
            "    keystone infra cdk sync-profile --profile {} --outputs {} --force",
            args.profile,
            dir.join("cdk-outputs.json").display()
        ));
    }
    context.note(format!("    keystone test --profile {}", args.profile));
    Ok(pending)
}

/// Step 7: switch the profile to the prepared identity, atomically.
fn activate(
    context: &Context,
    args: &RotateArgs,
    profile: &Profile,
    pending: Pending,
    path: &Path,
) -> Result<()> {
    let now = context.now_checked()?;
    let previous_key_id = profile.key_id.clone();
    let previous_certificate = profile.certificate_fingerprint_sha256.clone();

    // Confirm the prepared material is still usable before committing to it: an
    // identity file deleted between prepare and activate would otherwise leave the
    // profile pointing at a key that cannot sign.
    let mut candidate = profile.clone();
    candidate.key_id = Some(pending.key_id.clone());
    candidate.certificate_fingerprint_sha256 = Some(pending.certificate_fingerprint.clone());
    candidate.ca_fingerprint_sha256 = Some(pending.ca_fingerprint.clone());
    candidate.issuer = Some(IssuerMetadata::ephemeral(pending.certificate_expires_at));
    let loaded = crate::identity::load_identity(&context.store, &args.profile, &candidate, now)?;
    loaded
        .identity
        .verify_signing_path(b"keystone rotate activation probe")?;

    // One atomic write, so a profile is never left naming the new key with the old
    // certificate.
    let mut config = context.load_config()?;
    let entry = config.profile_mut(&args.profile)?;
    entry.key_id = candidate.key_id.clone();
    entry.certificate_fingerprint_sha256 = candidate.certificate_fingerprint_sha256.clone();
    entry.ca_fingerprint_sha256 = candidate.ca_fingerprint_sha256.clone();
    entry.issuer = candidate.issuer.clone();
    context.save_config(&config)?;

    // The cache holds credentials from the old identity. They are still valid, but
    // leaving them would mask a broken rotation until they expire.
    let cache = context.store.paths().credential_cache_file(&args.profile);
    if let Err(error) = std::fs::remove_file(&cache) {
        if error.kind() != std::io::ErrorKind::NotFound {
            context.detail(format!("could not clear {}: {error}", cache.display()));
        }
    }

    // The record has served its purpose. The old key and certificate stay on disk:
    // that is the rollback window in step 9.
    if let Err(error) = std::fs::remove_file(path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            context.detail(format!("could not remove {}: {error}", path.display()));
        }
    }

    context.note(format!(
        "Profile {:?} now uses key {}.",
        args.profile, pending.key_id
    ));
    context.note("");
    context.note("Point the profile at the new trust anchor and test it:");
    let outputs = pending
        .cdk_output
        .as_ref()
        .map(|dir| dir.join("cdk-outputs.json"))
        .unwrap_or_else(|| PathBuf::from("./keystone-rotation/cdk-outputs.json"));
    context.note(format!(
        "    keystone infra cdk sync-profile --profile {} --outputs {} --force",
        args.profile,
        outputs.display()
    ));
    context.note(format!("    keystone test --profile {}", args.profile));
    context.note("");
    context.note("Once that succeeds, disable the old trust anchor, and keep it briefly for");
    context.note("rollback before deleting it:");
    context.note(format!(
        "    keystone revoke --profile {}   # shows the disable command",
        args.profile
    ));
    if let (Some(key_id), Some(certificate)) = (&previous_key_id, &previous_certificate) {
        context.note("");
        context.note(format!(
            "The previous identity ({key_id}) and its certificate ({}) are still on disk for",
            certificate.display_short()
        ));
        context.note("rollback. Remove them when the new anchor is confirmed:");
        context.note(format!(
            "    rm {}",
            context.store.paths().identity_file(key_id).display()
        ));
        context.note(format!(
            "    rm -r {}",
            context.store.paths().certificate_dir(certificate).display()
        ));
    }
    Ok(())
}

fn existing_device_name(context: &Context, profile: &Profile) -> Option<String> {
    let fingerprint = profile.certificate_fingerprint_sha256.as_ref()?;
    let (leaf, _ca) = context.store.load_certificates(fingerprint).ok()?;
    let certificate = keystone_pki::ParsedCertificate::from_der(&leaf).ok()?;
    // The subject is rendered as `CN=..., OU=...`; take the common name.
    certificate.subject.split(',').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("CN")
            .then(|| value.trim().to_string())
    })
}

/// A stack name distinct from the profile's existing stack.
fn rotation_stack_name(profile_name: &str, key_id: &KeyId) -> String {
    let suffix: String = key_id
        .short()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let profile_part: String = profile_name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let mut name = String::from("Keystone");
    let mut chars = profile_part.chars();
    if let Some(first) = chars.next() {
        name.extend(first.to_uppercase());
        name.push_str(chars.as_str());
    }
    format!("{name}Rotation{suffix}")
}

fn pending_path(context: &Context, profile_name: &str) -> PathBuf {
    context
        .store
        .paths()
        .generated_dir(profile_name)
        .join("rotation.json")
}

fn write_pending(path: &Path, pending: &Pending, previous_key_id: &KeyId) -> Result<()> {
    let document = serde_json::json!({
        "version": 1,
        "key_id": pending.key_id.as_str(),
        "certificate_fingerprint_sha256": pending.certificate_fingerprint.as_str(),
        "ca_fingerprint_sha256": pending.ca_fingerprint.as_str(),
        "certificate_expires_at": keystone_core::time::format_rfc3339(pending.certificate_expires_at),
        "prepared_at": keystone_core::time::format_rfc3339(pending.prepared_at),
        "previous_key_id": previous_key_id.as_str(),
        "cdk_output": pending.cdk_output.as_ref().map(|path| path.display().to_string()),
    });
    let text = serde_json::to_string_pretty(&document).map_err(|error| {
        KeystoneError::Other(format!("cannot render the rotation record: {error}"))
    })?;
    // Under Keystone's data directory, so the directory is Keystone's to keep
    // private.
    if let Some(parent) = path.parent() {
        keystone_core::store::create_dir_all_private(parent)?;
    }
    write_atomic(path, format!("{text}\n").as_bytes())
}

fn read_pending(path: &Path) -> Result<Option<Pending>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(KeystoneError::io(
                format!("cannot read {}", path.display()),
                error,
            ))
        }
    };
    let document: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        KeystoneError::InvalidConfiguration(format!(
            "{} is not a usable rotation record ({error}). Delete it to start over.",
            path.display()
        ))
    })?;

    let field = |name: &str| -> Result<&str> {
        document
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                KeystoneError::InvalidConfiguration(format!(
                    "{} has no {name}. Delete it to start over.",
                    path.display()
                ))
            })
    };

    Ok(Some(Pending {
        key_id: KeyId::parse(field("key_id")?)?,
        certificate_fingerprint: Sha256Fingerprint::parse(field(
            "certificate_fingerprint_sha256",
        )?)?,
        ca_fingerprint: Sha256Fingerprint::parse(field("ca_fingerprint_sha256")?)?,
        certificate_expires_at: keystone_core::time::parse_rfc3339(field(
            "certificate_expires_at",
        )?)?,
        prepared_at: keystone_core::time::parse_rfc3339(field("prepared_at")?)?,
        // Absent when the rotation was prepared without `--generate-cdk`, and in a
        // record written by an earlier version.
        cdk_output: document
            .get("cdk_output")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rotation_stack_is_named_separately_from_the_original() {
        // Deploying the rotation over the original stack would replace the trust
        // anchor that is still in use.
        let key_id = KeyId::parse("01JZROTATE0000000000000000").unwrap();
        let name = rotation_stack_name("personal", &key_id);
        assert!(name.starts_with("KeystonePersonalRotation"), "{name}");
        assert_ne!(name, "KeystonePersonal");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric()), "{name}");
    }

    #[test]
    fn a_rotation_record_round_trips() {
        let dir = std::env::temp_dir().join(format!("keystone-rotate-{}", std::process::id()));
        let path = dir.join("rotation.json");
        let pending = Pending {
            key_id: KeyId::parse("01JZROTATE0000000000000000").unwrap(),
            certificate_fingerprint: Sha256Fingerprint::of(b"leaf"),
            ca_fingerprint: Sha256Fingerprint::of(b"ca"),
            certificate_expires_at: time::macros::datetime!(2031-07-25 0:00 UTC),
            prepared_at: time::macros::datetime!(2026-07-25 0:00 UTC),
            cdk_output: Some(PathBuf::from("/tmp/keystone-rotation")),
        };
        write_pending(
            &path,
            &pending,
            &KeyId::parse("01JZOLD00000000000000000000").unwrap(),
        )
        .unwrap();

        let read = read_pending(&path).unwrap().expect("a record");
        assert_eq!(read.key_id, pending.key_id);
        assert_eq!(
            read.certificate_fingerprint,
            pending.certificate_fingerprint
        );
        assert_eq!(read.ca_fingerprint, pending.ca_fingerprint);
        assert_eq!(read.certificate_expires_at, pending.certificate_expires_at);
        // So `--activate` can name the real outputs file rather than guessing.
        assert_eq!(read.cdk_output, pending.cdk_output);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_record_is_not_an_error() {
        // A first rotation has nothing prepared, which is the normal case.
        let path = std::env::temp_dir().join("keystone-rotate-absent/rotation.json");
        assert!(read_pending(&path).unwrap().is_none());
    }
}
