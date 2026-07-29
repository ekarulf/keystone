//! `keystone test` — prove the whole path works, printing no secrets.
//!
//! The design's sequence: validate the local identity, create a Roles Anywhere
//! session, validate the returned credentials, print the resulting ARN and
//! expiration, never print credential secrets. The cache is bypassed
//! deliberately: a test that a cached credential set is still valid says nothing
//! about whether the enclave and the trust anchor still agree.

use keystone_core::error::Result;

use crate::cli::TestArgs;
use crate::context::{print_line, Context};
use crate::exchange::{self, DebugSigning};

pub fn run(context: &Context, args: &TestArgs) -> Result<()> {
    let profile = context.load_profile(&args.profile)?;
    let now = context.now_checked()?;

    let loaded = crate::identity::load_identity(&context.store, &args.profile, &profile, now)?;
    // Local proof before any network call, so an enclave problem is not reported
    // as an AWS authentication failure.
    loaded
        .identity
        .verify_signing_path(b"keystone test signing probe")?;
    context.detail(format!(
        "the {} signed a probe that verifies against the certificate",
        crate::backend::KEY_STORE
    ));
    context.detail(format!(
        "presenting {} (serial {}) issued by {}",
        loaded.certificate.subject,
        loaded.certificate.serial_decimal,
        loaded.ca_certificate.subject
    ));

    let request = exchange::session_request(&args.profile, &profile)?;
    let exchanged = exchange::exchange(
        context,
        &profile,
        &loaded,
        &request,
        now,
        DebugSigning {
            enabled: args.debug_signing,
            redact: args.redact,
        },
    )?;

    print_line("IAM Roles Anywhere authentication succeeded.")?;
    print_line("")?;
    match &exchanged.assumed_role_arn {
        Some(arn) => {
            print_line("Caller ARN:")?;
            print_line(arn)?;
        }
        None => {
            // Roles Anywhere does not always report it; the requested role is
            // still worth printing so the output identifies what was tested.
            print_line("Requested role:")?;
            print_line(&request.role_arn)?;
        }
    }
    print_line("")?;
    print_line("Credentials expire:")?;
    print_line(&keystone_core::time::format_rfc3339(
        exchanged.credentials.expiration,
    ))?;
    print_line("")?;
    print_line(&format!(
        "Access key ID: {}",
        exchanged.credentials.access_key_id
    ))?;

    if exchanged.attempts.len() > 1 {
        context.note(format!(
            "note: succeeded after {} attempts; see `keystone doctor` if this repeats",
            exchanged.attempts.len()
        ));
    }
    Ok(())
}
