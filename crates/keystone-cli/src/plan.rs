//! Turning `--policy`/`--managed-policy-arn`/`--existing-*` flags into a plan.
//!
//! Shared by `keystone infra cdk *`, `keystone bootstrap --generate-cdk`, and
//! `keystone rotate --generate-cdk`, so all three refuse the same policies and
//! resolve the same defaults.

use std::path::Path;

use keystone_core::config::Profile;
use keystone_core::error::{KeystoneError, Result};
use keystone_infra::plan::PlanRequest;
use keystone_infra::{CdkPlan, PermissionMode};

use crate::cli::CdkPlanArgs;
use crate::context::Context;

/// Build a plan for a profile, reading the CA certificate Keystone stored.
pub fn build(context: &Context, args: &CdkPlanArgs, profile: &Profile) -> Result<CdkPlan> {
    let permissions = permissions(args)?;
    let ca_certificate_pem = ca_certificate_pem(context, profile)?;

    CdkPlan::build(
        PlanRequest {
            profile_name: args.profile.clone(),
            stack_name: args.stack_name.clone(),
            role_name: args.role_name.clone(),
            trust_anchor_name: args.trust_anchor_name.clone(),
            roles_anywhere_profile_name: args.roles_anywhere_profile_name.clone(),
            existing_trust_anchor_arn: args.existing_trust_anchor_arn.clone(),
            existing_role_arn: args.existing_role_arn.clone(),
            permissions,
            duration_seconds: args.duration_seconds,
            ca_certificate_pem,
        },
        profile,
    )
}

/// Read `--policy` or `--managed-policy-arn`, refusing both at once.
fn permissions(args: &CdkPlanArgs) -> Result<Option<PermissionMode>> {
    match (&args.policy, args.managed_policy_arn.as_slice()) {
        (Some(_), [_, ..]) => Err(KeystoneError::InvalidConfiguration(
            "--policy and --managed-policy-arn cannot be combined; choose an inline document or \
             managed policies"
                .to_string(),
        )),
        (Some(path), []) => Ok(Some(PermissionMode::inline(&read_policy(path)?)?)),
        (None, [_, ..]) => Ok(Some(PermissionMode::managed(
            args.managed_policy_arn.clone(),
        )?)),
        // The design's default: a role with no workload permissions.
        (None, []) => Ok(None),
    }
}

fn read_policy(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|error| KeystoneError::io(format!("cannot read {}", path.display()), error))
}

/// The stored CA certificate as PEM, when the profile has one.
///
/// Absent is not an error here: `--existing-trust-anchor-arn` needs no local CA,
/// and `CdkPlan::build` produces the message naming both options when neither is
/// available.
fn ca_certificate_pem(context: &Context, profile: &Profile) -> Result<Option<String>> {
    let Some(fingerprint) = &profile.certificate_fingerprint_sha256 else {
        return Ok(None);
    };
    let (_leaf, ca_der) = context.store.load_certificates(fingerprint)?;
    Ok(Some(
        keystone_pki::ParsedCertificate::from_der(&ca_der)?.to_pem(),
    ))
}
