//! `keystone profiles` — one line per configured profile.

use keystone_core::error::Result;

use crate::context::{print_line, Context};

pub fn run(context: &Context) -> Result<()> {
    let config = context.load_config()?;
    if config.profiles.is_empty() {
        context.note("No profiles are configured yet.");
        context.note("");
        context.note("Create one:");
        context.note(
            "    keystone bootstrap --profile personal --region us-east-1 --device-name my-laptop",
        );
        return Ok(());
    }

    for (name, profile) in &config.profiles {
        let state = if profile.key_id.is_none() {
            "no identity"
        } else if profile.certificate_fingerprint_sha256.is_none() {
            "awaiting certificate"
        } else if profile.require_ready(name).is_err() {
            "awaiting sync-profile"
        } else {
            "ready"
        };
        print_line(&format!("{name}\t{}\t{state}", profile.region))?;
    }
    Ok(())
}
