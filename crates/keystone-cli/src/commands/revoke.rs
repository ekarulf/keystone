//! `keystone revoke` — explain how to revoke this device's access.
//!
//! Deliberately advisory. Revocation is a change to deployed AWS infrastructure,
//! and Keystone does not deploy or modify infrastructure; it also cannot know
//! whether disabling the trust anchor would cut off other devices sharing it. So
//! this prints the exact commands, naming this profile's resources, and leaves
//! the decision with the operator.

use keystone_core::error::Result;

use crate::cli::ProfileArgs;
use crate::context::{print_line, Context};

pub fn run(context: &Context, args: &ProfileArgs) -> Result<()> {
    let profile = context.load_profile(&args.profile)?;

    print_line(&format!(
        "To revoke profile {:?}, disable its IAM Roles Anywhere trust anchor.",
        args.profile
    ))?;
    print_line("")?;
    print_line("New CreateSession requests then fail. AWS credentials already issued remain")?;
    print_line(&format!(
        "valid until they expire, at most {} seconds from when they were issued.",
        profile.duration_seconds
    ))?;
    print_line("")?;

    let region = &profile.region;
    print_line("Disable the trust anchor:")?;
    print_line(&format!(
        "    aws rolesanywhere disable-trust-anchor --region {region} --trust-anchor-id {}",
        id_of(&profile.trust_anchor_arn)
    ))?;
    print_line("")?;
    print_line("For emergency response, also consider:")?;
    print_line(&format!(
        "    aws rolesanywhere disable-profile --region {region} --profile-id {}",
        id_of(&profile.roles_anywhere_profile_arn)
    ))?;
    print_line("  - removing the IAM role from the Roles Anywhere profile;")?;
    print_line(&format!(
        "  - modifying the trust policy of {};",
        profile.role_arn
    ))?;
    print_line("  - revoking active application access where possible.")?;
    print_line("")?;
    print_line("To make this device's identity unusable locally as well:")?;
    print_line(&format!(
        "    keystone rotate --profile {} --activate",
        args.profile
    ))?;

    // The hardware key is not deleted here. Deleting it would make the
    // profile unusable before the operator has confirmed the AWS-side change took
    // effect, and it cannot be undone.
    context.note("");
    context.note("No local or AWS state was changed by this command.");
    Ok(())
}

/// The resource id at the end of an ARN, for the CLI flags that want an id.
fn id_of(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_arn_yields_the_bare_resource_id() {
        // `aws rolesanywhere disable-trust-anchor` takes an id, not an ARN, so
        // pasting the ARN would fail.
        assert_eq!(
            id_of("arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcd-1234"),
            "abcd-1234"
        );
        // A placeholder passes through unchanged rather than becoming empty.
        assert_eq!(id_of("TBD"), "TBD");
    }
}
