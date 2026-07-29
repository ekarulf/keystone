//! `keystone init` — create a hardware-backed identity and nothing else.
//!
//! The command for enrolling with an existing CA: it produces the key whose
//! public half `keystone enroll csr` then asks the CA to certify. It writes no
//! certificate, so the profile it leaves behind is deliberately incomplete.

use crate::backend::{DeviceKey, KeyPolicy};
use keystone_core::config::{validate_profile_name, validate_region, Profile};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;

use crate::cli::InitArgs;
use crate::context::Context;

pub fn run(context: &Context, args: &InitArgs) -> Result<()> {
    validate_profile_name(&args.profile)?;
    validate_region(&args.region)?;

    let mut config = context.load_config()?;
    if let Some(existing) = config.profiles.get(&args.profile) {
        // Replacing the identity orphans the certificate issued for the old key,
        // and for an ephemeral CA that certificate can never be reissued. So this
        // needs to be an explicit choice.
        if existing.key_id.is_some() && !args.force {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "profile {:?} already has an identity ({}). Pass --force to replace it, which \
                 makes its certificate unusable, or use a different --profile.",
                args.profile,
                existing
                    .key_id
                    .as_ref()
                    .map(KeyId::short)
                    .unwrap_or_default()
            )));
        }
    }

    let now = context.now_checked()?;
    let key_id = KeyId::generate();
    let policy = KeyPolicy::default();

    context.detail(format!(
        "generating a {} P-256 signing key ({})",
        crate::backend::KEY_STORE,
        policy.describe()
    ));
    let generated = DeviceKey::generate(key_id.clone(), policy, now)?;

    // Metadata first: a key with no metadata is unreachable, whereas metadata
    // whose profile entry is missing is merely unused.
    context.store.save_identity(&generated.metadata)?;

    let profile = config
        .profiles
        .entry(args.profile.clone())
        .or_insert_with(|| Profile::new(&args.region));
    profile.region = args.region.clone();
    profile.key_id = Some(key_id.clone());
    profile.key_accessibility = policy.accessibility();
    if let Some(session_name) = &args.role_session_name {
        keystone_core::config::validate_role_session_name(session_name)?;
        profile.role_session_name = Some(session_name.clone());
    }
    // A previous identity's certificate does not describe this key.
    profile.certificate_fingerprint_sha256 = None;
    profile.ca_fingerprint_sha256 = None;
    profile.issuer = None;

    context.save_config(&config)?;

    context.note(format!(
        "Created {} identity {key_id}",
        crate::backend::KEY_STORE
    ));
    context.note(format!(
        "Public-key fingerprint: {}",
        generated
            .metadata
            .public_key_fingerprint_sha256
            .display_short()
    ));
    context.note(format!("Device URI SAN: {}", key_id.device_san_uri()));
    context.note(format!("Profile: {}", args.profile));
    context.note("");
    context.note("Next, obtain a certificate for this key:");
    context.note(format!(
        "    keystone enroll csr --profile {} --output device.csr",
        args.profile
    ));
    context.note(format!(
        "    keystone enroll install --profile {} --certificate leaf.pem --chain issuer.pem",
        args.profile
    ));
    Ok(())
}
