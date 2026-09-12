//! `keystone` — hardware-backed temporary AWS credentials.
//!
//! This is a dispatch table and an exit-code policy, nothing more. Every command
//! lives in [`commands`] and returns `Result<()>`; failures are reported on
//! standard error and exit nonzero, which is what the AWS `credential_process`
//! contract requires of a failed credential fetch.

mod backend;
mod cli;
mod commands;
mod context;
mod exchange;
#[cfg(unix)]
mod google;
mod identity;
mod plan;
mod ssh;

use std::process::ExitCode;

use clap::Parser as _;
use keystone_core::error::{KeystoneError, Result};

use crate::cli::{Cli, Command, InfraCommand};
use crate::context::Context;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            // Any nonzero status marks the failure. A single code keeps the
            // contract simple: callers distinguish causes from the message, not
            // from an exit-code table Keystone would then have to keep stable.
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let context = Context::new(cli.home.clone(), cli.allow_unsafe_permissions, cli.verbose)?;
    match &cli.command {
        Command::Ssh(command) => ssh::run(&context, command),
        Command::Init(args) => commands::init::run(&context, args),
        Command::Bootstrap(args) => commands::bootstrap::run(&context, args),
        Command::Enroll(command) => commands::enroll::run(&context, command),
        Command::CredentialProcess(args) => commands::credential_process::run(&context, args),
        Command::Inspect(args) => commands::inspect::run(&context, args),
        Command::Test(args) => commands::test::run(&context, args),
        Command::Doctor(args) => commands::doctor::run(&context, args),
        Command::Rotate(args) => commands::rotate::run(&context, args),
        Command::Revoke(args) => commands::revoke::run(&context, args),
        Command::GoogleToken(args) => {
            #[cfg(unix)]
            {
                google::run(&context, args)
            }
            #[cfg(not(unix))]
            {
                let _ = args;
                Err(KeystoneError::Other(
                    "Google token storage currently requires Unix".into(),
                ))
            }
        }
        Command::Profiles => commands::profiles::run(&context),
        Command::Infra(InfraCommand::Cdk(command)) => commands::infra::run(&context, command),
    }
}

/// Print a failure to standard error, including the chain of causes.
///
/// Standard error, never standard output: `credential-process` shares this exit
/// path, and a diagnostic on standard output would be parsed as credential JSON.
fn report(error: &KeystoneError) {
    eprintln!("keystone: {error}");

    // The top-level message names what Keystone was doing; the sources name what
    // actually went wrong (a missing file, a TLS failure). Both matter, and
    // `Display` on the outer error shows only the first.
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
