//! The command-line surface.
//!
//! Kept separate from the command implementations so the whole grammar can be
//! read in one place, and so parsing can be tested without touching the hardware
//! key store, the filesystem, or the network.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Hardware-backed temporary AWS credentials.
#[derive(Debug, Parser)]
#[command(
    name = "keystone",
    version,
    about = "Hardware-backed temporary AWS credentials",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Override Keystone's data directory (also honored as KEYSTONE_HOME).
    #[arg(long, global = true, value_name = "DIR")]
    pub home: Option<PathBuf>,

    /// Accept a configuration file other local users can write.
    ///
    /// Keystone refuses such a file by default: another user who can edit it can
    /// redirect Keystone at a role or trust anchor of their choosing.
    #[arg(long, global = true)]
    pub allow_unsafe_permissions: bool,

    /// Print more diagnostic detail on standard error.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage Secure Enclave SSH identities and their agent sockets.
    #[command(subcommand)]
    Ssh(SshCommand),
    /// Create a hardware-backed identity without issuing a certificate.
    Init(InitArgs),
    /// Create an identity, issue a certificate from a one-shot CA, and destroy the CA key.
    Bootstrap(BootstrapArgs),
    /// Enroll with an existing certificate authority.
    #[command(subcommand)]
    Enroll(EnrollCommand),
    /// Manage a reusable AWS KMS-backed certificate authority.
    #[command(subcommand)]
    Ca(CaCommand),
    /// Print temporary credentials in the AWS credential_process format.
    CredentialProcess(CredentialProcessArgs),
    /// Print a short-lived ES256 service token signed by the device identity.
    Token(TokenArgs),
    /// Show what Keystone knows about a profile. Prints no secrets.
    Inspect(ProfileArgs),
    /// Exchange the device identity for credentials and report the result.
    Test(TestArgs),
    /// Run every local and remote check and report what is wrong.
    Doctor(ProfileArgs),
    /// Replace the identity, certificate, and trust anchor.
    Rotate(RotateArgs),
    /// Explain how to revoke this device's access.
    Revoke(ProfileArgs),
    /// List the configured profiles.
    Profiles,
    /// Print a scoped Google service-account token using the profile’s fixed policy (Unix).
    GoogleToken(ProfileArgs),
    /// Generate and synchronize AWS infrastructure.
    #[command(subcommand)]
    Infra(InfraCommand),
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    /// Create an SSH identity, public key, and SSH config snippet (idempotent).
    Init(SshArgs),
    /// Print the OpenSSH public key.
    PublicKey(SshArgs),
    /// Print the SSH configuration for this identity.
    Config(SshArgs),
    /// Serve the SSH agent socket in the foreground.
    Agent(SshArgs),
}

#[derive(Debug, Args)]
pub struct SshArgs {
    /// Identity name, also used as the public-key comment.
    #[arg(default_value = "my-keystone-id")]
    pub name: String,
}

/// Which profile to act on. Most commands need only this.
#[derive(Debug, Args)]
pub struct ProfileArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct TokenArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// Exact HTTPS issuer value placed in the JWT.
    #[arg(long)]
    pub issuer: String,

    /// Exact HTTPS audience value placed in the JWT.
    #[arg(long)]
    pub audience: String,

    /// Token lifetime from 1m through 15m.
    #[arg(long = "ttl", default_value = "5m", value_parser = parse_token_ttl)]
    pub ttl_minutes: i64,
}

fn parse_token_ttl(value: &str) -> std::result::Result<i64, String> {
    let minutes = value
        .strip_suffix('m')
        .and_then(|digits| {
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                None
            } else {
                digits.parse::<i64>().ok()
            }
        })
        .ok_or_else(|| "TTL must be a whole number of minutes, such as 5m".to_string())?;
    if !(1..=15).contains(&minutes) {
        return Err("TTL must be between 1m and 15m".to_string());
    }
    Ok(minutes)
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The AWS Region the profile will use.
    #[arg(long)]
    pub region: String,

    /// The role session name reported to CloudTrail.
    #[arg(long)]
    pub role_session_name: Option<String>,

    /// Replace an existing profile's identity.
    ///
    /// The previous hardware key becomes unusable, so any certificate
    /// issued for it stops working.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct BootstrapArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    #[arg(long)]
    pub region: String,

    /// The device name placed in the certificate's common name.
    #[arg(long)]
    pub device_name: String,

    /// The organization placed in the certificate subject.
    #[arg(long)]
    pub organization: Option<String>,

    #[arg(long)]
    pub role_session_name: Option<String>,

    /// How the issuing CA is obtained. Only `ephemeral` is implemented.
    #[arg(long, default_value = "ephemeral", value_parser = ["ephemeral"])]
    pub ca_mode: String,

    /// Device certificate lifetime, as a number of years, months, or days.
    #[arg(long, default_value = "5y")]
    pub leaf_validity: String,

    /// CA certificate lifetime. Must outlast the device certificate.
    #[arg(long, default_value = "10y")]
    pub ca_validity: String,

    /// Also write the CDK project that creates the AWS resources.
    #[arg(long, value_name = "DIR")]
    pub generate_cdk: Option<PathBuf>,

    /// Write the public bootstrap artifacts here.
    #[arg(long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Replace an existing profile's identity and certificate.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Subcommand)]
pub enum EnrollCommand {
    /// Write a PKCS#10 CSR for the hardware key.
    Csr(EnrollCsrArgs),
    /// Install a certificate issued for the hardware key.
    Install(EnrollInstallArgs),
}

#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Create a self-signed CA certificate for an existing KMS key.
    Init(CaInitArgs),
    /// Issue a device certificate from a Keystone CSR.
    Issue(CaIssueArgs),
}

#[derive(Debug, Args)]
pub struct KmsArgs {
    /// Existing asymmetric KMS key ARN, key ID, or alias.
    #[arg(long)]
    pub kms_key: String,

    /// AWS Region containing the KMS key.
    #[arg(long)]
    pub region: String,

    /// Named AWS configuration profile to use.
    #[arg(long)]
    pub aws_profile: Option<String>,
}

#[derive(Debug, Args)]
pub struct CaInitArgs {
    #[command(flatten)]
    pub kms: KmsArgs,

    /// CA subject, as `CN=...,O=...` with optional `OU=...`.
    #[arg(long)]
    pub subject: String,

    /// CA certificate lifetime.
    #[arg(long, default_value = "10y", value_parser = parse_validity_arg)]
    pub validity: String,

    /// Destination for the validated CA certificate.
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct CaIssueArgs {
    #[command(flatten)]
    pub kms: KmsArgs,

    /// Self-signed CA certificate created by `keystone ca init`.
    #[arg(long)]
    pub ca_certificate: PathBuf,

    /// PKCS#10 request created by `keystone enroll csr`.
    #[arg(long)]
    pub csr: PathBuf,

    /// Issued device-certificate lifetime.
    #[arg(long, default_value = "1y", value_parser = parse_validity_arg)]
    pub validity: String,

    /// Destination for the validated device certificate.
    #[arg(long)]
    pub output: PathBuf,
}

fn parse_validity_arg(value: &str) -> std::result::Result<String, String> {
    crate::context::parse_validity(value)
        .map(|_| value.to_string())
        .map_err(|error| error.to_string())
}

#[derive(Debug, Args)]
pub struct EnrollCsrArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The certificate subject, as `CN=...,OU=...,O=...`.
    #[arg(long)]
    pub subject: Option<String>,

    /// The device name, used when `--subject` is not given.
    #[arg(long)]
    pub device_name: Option<String>,

    /// The URI SAN to request.
    ///
    /// Defaults to this profile's `urn:keystone:device:<key-id>`; a different
    /// value is refused, because the trust policy authorizes that URI.
    #[arg(long)]
    pub san_uri: Option<String>,

    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct EnrollInstallArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The issued device certificate, PEM or DER.
    #[arg(long)]
    pub certificate: PathBuf,

    /// The issuing chain, leaf-to-root, as a PEM bundle.
    #[arg(long)]
    pub chain: PathBuf,
}

#[derive(Debug, Args)]
pub struct CredentialProcessArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// Print the canonical request and string-to-sign to standard error.
    ///
    /// Signatures and credentials stay redacted; `--redact false` is a separate,
    /// deliberate step.
    #[arg(long)]
    pub debug_signing: bool,

    /// Redact sensitive values in debug output. On by default.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub redact: bool,

    /// Ignore any cached credentials and perform a fresh exchange.
    #[arg(long)]
    pub no_cache: bool,
}

#[derive(Debug, Args)]
pub struct TestArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// Print the canonical request and string-to-sign to standard error.
    #[arg(long)]
    pub debug_signing: bool,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub redact: bool,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    #[arg(long, default_value = "ephemeral", value_parser = ["ephemeral"])]
    pub ca_mode: String,

    #[arg(long)]
    pub device_name: Option<String>,

    #[arg(long)]
    pub organization: Option<String>,

    #[arg(long, default_value = "5y")]
    pub leaf_validity: String,

    #[arg(long, default_value = "10y")]
    pub ca_validity: String,

    /// Where to write the CDK project for the new trust anchor.
    #[arg(long, value_name = "DIR")]
    pub generate_cdk: Option<PathBuf>,

    /// Switch the profile to the new identity now.
    ///
    /// Without this, `rotate` prepares the new identity and stops before the
    /// switch, so the new trust anchor can be deployed and tested first.
    #[arg(long)]
    pub activate: bool,
}

#[derive(Debug, Subcommand)]
pub enum InfraCommand {
    /// Generate a TypeScript CDK project.
    #[command(subcommand)]
    Cdk(CdkCommand),
}

#[derive(Debug, Subcommand)]
pub enum CdkCommand {
    /// Write a complete CDK project to a directory.
    Init(CdkInitArgs),
    /// Print the project that would be generated, without writing anything.
    Print(CdkPrintArgs),
    /// Render one generated file to standard output.
    Render(CdkRenderArgs),
    /// Copy the deployed ARNs from `cdk-outputs.json` into the profile.
    SyncProfile(CdkSyncProfileArgs),
}

/// The generation flags, shared by `init`, `print`, and `render`.
#[derive(Debug, Args, Clone)]
pub struct CdkPlanArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    #[arg(long)]
    pub stack_name: Option<String>,

    #[arg(long)]
    pub role_name: Option<String>,

    #[arg(long)]
    pub trust_anchor_name: Option<String>,

    /// The IAM Roles Anywhere profile name, if it should differ from the default.
    #[arg(long)]
    pub roles_anywhere_profile_name: Option<String>,

    /// Reuse an existing trust anchor instead of creating one.
    #[arg(long)]
    pub existing_trust_anchor_arn: Option<String>,

    /// Reference an externally managed role. The stack will not modify it.
    #[arg(long)]
    pub existing_role_arn: Option<String>,

    /// An IAM policy document to attach inline to the generated role.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// A managed policy to attach. May be repeated.
    ///
    /// Account-wide policies such as AdministratorAccess are refused.
    #[arg(long, value_name = "ARN")]
    pub managed_policy_arn: Vec<String>,

    /// Session duration for the generated profile and role.
    #[arg(long)]
    pub duration_seconds: Option<u32>,
}

#[derive(Debug, Args)]
pub struct CdkInitArgs {
    #[command(flatten)]
    pub plan: CdkPlanArgs,

    #[arg(long, value_name = "DIR")]
    pub output: PathBuf,

    /// Overwrite generated files that have been modified.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CdkPrintArgs {
    #[command(flatten)]
    pub plan: CdkPlanArgs,
}

#[derive(Debug, Args)]
pub struct CdkRenderArgs {
    #[command(flatten)]
    pub plan: CdkPlanArgs,

    /// Which generated file to print, e.g. `lib/keystone-personal-stack.ts`.
    #[arg(long)]
    pub file: String,
}

#[derive(Debug, Args)]
pub struct CdkSyncProfileArgs {
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// The `cdk deploy --outputs-file` output.
    #[arg(long, value_name = "FILE")]
    pub outputs: PathBuf,

    /// Which stack to read, when the outputs file holds more than one.
    #[arg(long)]
    pub stack_name: Option<String>,

    /// Replace values that conflict with what the profile already records.
    #[arg(long)]
    pub force: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn the_command_grammar_is_internally_consistent() {
        // clap's own audit: duplicate long flags, conflicting short flags, and
        // subcommands that shadow each other are all caught here rather than at
        // the first run.
        Cli::command().debug_assert();
    }

    #[test]
    fn every_command_in_the_design_parses() {
        // The design's "CLI Overview" list, verbatim, with the arguments each
        // command needs.
        let invocations: &[&[&str]] = &[
            &[
                "keystone",
                "init",
                "--profile",
                "personal",
                "--region",
                "us-east-1",
            ],
            &[
                "keystone",
                "bootstrap",
                "--profile",
                "personal",
                "--region",
                "us-east-1",
                "--device-name",
                "example-laptop",
                "--ca-mode",
                "ephemeral",
                "--leaf-validity",
                "5y",
                "--ca-validity",
                "10y",
                "--generate-cdk",
                "./keystone-infra",
            ],
            &[
                "keystone",
                "enroll",
                "csr",
                "--profile",
                "personal",
                "--subject",
                "CN=example-laptop,OU=Keystone Devices,O=Example",
                "--san-uri",
                "urn:keystone:device:019c",
                "--output",
                "example-laptop.csr",
            ],
            &[
                "keystone",
                "enroll",
                "install",
                "--profile",
                "personal",
                "--certificate",
                "leaf.pem",
                "--chain",
                "issuer.pem",
            ],
            &[
                "keystone",
                "ca",
                "init",
                "--kms-key",
                "arn:aws:kms:us-east-2:123456789012:key/example",
                "--region",
                "us-east-2",
                "--subject",
                "CN=Keystone KMS CA,O=Example",
                "--output",
                "ca.pem",
            ],
            &[
                "keystone",
                "ca",
                "issue",
                "--kms-key",
                "alias/keystone-ca",
                "--region",
                "us-east-2",
                "--aws-profile",
                "administrator",
                "--ca-certificate",
                "ca.pem",
                "--csr",
                "device.csr",
                "--output",
                "device.pem",
            ],
            &["keystone", "inspect", "--profile", "personal"],
            &["keystone", "credential-process", "--profile", "personal"],
            &["keystone", "test", "--profile", "personal"],
            &["keystone", "doctor", "--profile", "personal"],
            &[
                "keystone",
                "rotate",
                "--profile",
                "personal",
                "--ca-mode",
                "ephemeral",
                "--generate-cdk",
                "./keystone-rotation",
            ],
            &["keystone", "revoke", "--profile", "personal"],
            &["keystone", "profiles"],
            &[
                "keystone",
                "infra",
                "cdk",
                "init",
                "--profile",
                "personal",
                "--output",
                "./keystone-infra",
                "--stack-name",
                "KeystonePersonal",
                "--role-name",
                "KeystonePersonalMac",
            ],
            &["keystone", "infra", "cdk", "print", "--profile", "personal"],
            &[
                "keystone",
                "infra",
                "cdk",
                "render",
                "--profile",
                "personal",
                "--file",
                "lib/keystone-personal-stack.ts",
            ],
            &[
                "keystone",
                "infra",
                "cdk",
                "sync-profile",
                "--profile",
                "personal",
                "--outputs",
                "./cdk-outputs.json",
            ],
        ];

        for argv in invocations {
            Cli::try_parse_from(*argv)
                .unwrap_or_else(|error| panic!("{}: {error}", argv.join(" ")));
        }
    }

    #[test]
    fn ca_commands_have_secure_defaults_and_required_arguments() {
        let init = Cli::try_parse_from([
            "keystone",
            "ca",
            "init",
            "--kms-key",
            "key-id",
            "--region",
            "us-east-2",
            "--subject",
            "CN=Example",
            "--output",
            "ca.pem",
        ])
        .unwrap();
        let Command::Ca(CaCommand::Init(args)) = init.command else {
            panic!("wrong command")
        };
        assert_eq!(args.validity, "10y");

        let issue = Cli::try_parse_from([
            "keystone",
            "ca",
            "issue",
            "--kms-key",
            "key-id",
            "--region",
            "us-east-2",
            "--ca-certificate",
            "ca.pem",
            "--csr",
            "device.csr",
            "--output",
            "device.pem",
        ])
        .unwrap();
        let Command::Ca(CaCommand::Issue(args)) = issue.command else {
            panic!("wrong command")
        };
        assert_eq!(args.validity, "1y");

        assert!(Cli::try_parse_from([
            "keystone",
            "ca",
            "init",
            "--region",
            "us-east-2",
            "--subject",
            "CN=Example",
            "--output",
            "ca.pem",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "keystone",
            "ca",
            "issue",
            "--kms-key",
            "key-id",
            "--region",
            "us-east-2",
            "--ca-certificate",
            "ca.pem",
            "--csr",
            "device.csr",
            "--validity",
            "forever",
            "--output",
            "device.pem",
        ])
        .is_err());
    }

    #[test]
    fn debug_signing_redacts_unless_redaction_is_switched_off() {
        // The design: "Even then, authorization signatures and credentials should
        // remain redacted by default."
        let cli = Cli::try_parse_from([
            "keystone",
            "credential-process",
            "--profile",
            "personal",
            "--debug-signing",
        ])
        .unwrap();
        let Command::CredentialProcess(args) = cli.command else {
            panic!("wrong command");
        };
        assert!(args.debug_signing);
        assert!(args.redact, "redaction must be the default");

        let cli = Cli::try_parse_from([
            "keystone",
            "credential-process",
            "--debug-signing",
            "--redact",
            "false",
        ])
        .unwrap();
        let Command::CredentialProcess(args) = cli.command else {
            panic!("wrong command");
        };
        assert!(!args.redact);
    }

    #[test]
    fn repeated_managed_policy_arns_accumulate() {
        let cli = Cli::try_parse_from([
            "keystone",
            "infra",
            "cdk",
            "init",
            "--output",
            ".",
            "--managed-policy-arn",
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "--managed-policy-arn",
            "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess",
        ])
        .unwrap();
        let Command::Infra(InfraCommand::Cdk(CdkCommand::Init(args))) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.plan.managed_policy_arn.len(), 2);
        assert!(!args.force);
    }

    #[test]
    fn a_bad_ca_mode_is_refused_at_parse_time() {
        // `--ca-mode acm-pca` is a plausible guess, and failing at parse time says
        // what is supported instead of failing partway through a bootstrap.
        assert!(Cli::try_parse_from([
            "keystone",
            "bootstrap",
            "--region",
            "us-east-1",
            "--device-name",
            "mac",
            "--ca-mode",
            "acm-pca",
        ])
        .is_err());
    }

    #[test]
    fn global_flags_are_accepted_after_the_subcommand() {
        // Where a user actually types them.
        let cli = Cli::try_parse_from([
            "keystone",
            "inspect",
            "--profile",
            "personal",
            "--home",
            "/tmp/keystone",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(cli.home.unwrap().to_str(), Some("/tmp/keystone"));
        assert!(cli.verbose);
    }

    #[test]
    fn the_default_profile_is_named_default() {
        // So a single-profile installation never has to pass --profile.
        let cli = Cli::try_parse_from(["keystone", "inspect"]).unwrap();
        let Command::Inspect(args) = cli.command else {
            panic!("wrong command");
        };
        assert_eq!(args.profile, "default");
    }

    #[test]
    fn token_ttl_defaults_and_bounds() {
        let base = [
            "keystone",
            "token",
            "--issuer",
            "https://auth.example.com",
            "--audience",
            "https://api.example.com",
        ];
        let cli = Cli::try_parse_from(base).unwrap();
        let Command::Token(args) = cli.command else {
            panic!("wrong command")
        };
        assert_eq!(args.ttl_minutes, 5);
        assert_eq!(args.profile, "default");
        for ttl in ["1m", "15m"] {
            let cli = Cli::try_parse_from(base.into_iter().chain(["--ttl", ttl])).unwrap();
            let Command::Token(args) = cli.command else {
                panic!("wrong command")
            };
            assert_eq!(args.ttl_minutes, if ttl == "1m" { 1 } else { 15 });
        }
        for ttl in ["0m", "16m", "5", "abc", "1h", "-1m"] {
            assert!(
                Cli::try_parse_from(base.into_iter().chain(["--ttl", ttl])).is_err(),
                "{ttl}"
            );
        }
    }
}
