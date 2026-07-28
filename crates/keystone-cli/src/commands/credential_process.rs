//! `keystone credential-process` — the AWS process credential provider.
//!
//! The design's rules, which this module exists to enforce:
//!
//! * credential JSON is the only content written to standard output;
//! * diagnostics go to standard error;
//! * successful output ends with a newline;
//! * credential values are never logged;
//! * failures exit nonzero;
//! * no partial JSON is written on failure.
//!
//! The last rule is why the document is serialized to a `String` in full before
//! a single byte reaches standard output: a serializer writing straight to stdout
//! could emit `{"Version":1,` and then fail, and the SDK would report a JSON
//! parse error instead of the real cause.

use keystone_core::error::{KeystoneError, Result};

use crate::cli::CredentialProcessArgs;
use crate::context::{print_line, Context};
use crate::exchange::{self, CredentialSource, DebugSigning};

pub fn run(context: &Context, args: &CredentialProcessArgs) -> Result<()> {
    let profile = context.load_profile(&args.profile)?;
    let now = context.now_checked()?;
    let loaded = crate::identity::load_identity(&context.store, &args.profile, &profile, now)?;

    let exchanged = exchange::credentials_for(
        context,
        &args.profile,
        &profile,
        &loaded,
        now,
        !args.no_cache,
        DebugSigning {
            enabled: args.debug_signing,
            redact: args.redact,
        },
    )?;

    let document =
        serde_json::to_string(&exchanged.credentials.to_process_output()).map_err(|error| {
            KeystoneError::Other(format!("cannot serialize the credential document: {error}"))
        })?;

    // `print_line` appends the newline the contract requires and flushes, so a
    // closed pipe is an error here rather than a silent empty response.
    print_line(&document)?;

    // Only after the credentials are safely out: a diagnostic is not worth
    // risking the ordering of the one stream the SDK reads.
    match exchanged.source {
        CredentialSource::Cache => context.detail("served from the credential cache"),
        CredentialSource::Exchange => context.detail(format!(
            "obtained fresh credentials in {} attempt(s)",
            exchanged.attempts.len().max(1)
        )),
        CredentialSource::CacheAfterFailedRefresh => {}
    }
    Ok(())
}
