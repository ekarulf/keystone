//! Infrastructure generation for Keystone.
//!
//! Turns a local Keystone profile into a TypeScript CDK project that creates the
//! IAM Roles Anywhere trust anchor, profile, and role the device needs — and,
//! after deployment, reads the CloudFormation outputs back into the profile.
//!
//! Two rules shape this crate:
//!
//! *Generation only.* Nothing here calls AWS. `keystone infra cdk init` writes
//! files; deciding to create IAM roles in an account is the operator's call, made
//! with credentials they chose after reading `cdk diff`. The design states it
//! plainly: "Keystone source generation must not automatically run `cdk deploy`."
//!
//! *Public data only.* The generated project embeds the CA certificate, the
//! device's URI SAN, and fingerprints. It never contains the Secure Enclave key
//! reference, and it never contains a CA private key — for an ephemeral-CA
//! profile that key was destroyed before this code could see it. [`plan`] carries
//! only public fields, so there is nothing secret to hand a template.

pub mod outputs;
pub mod plan;
pub mod project;
pub mod sync;
pub mod template;

pub use outputs::StackOutputs;
pub use plan::{CdkPlan, PermissionMode, RoleTarget, TrustAnchorTarget};
pub use project::{GeneratedFile, GeneratedProject, WriteOutcome, WriteReport};
pub use sync::{sync_profile, FieldOutcome, SyncReport};
pub use template::TEMPLATE_VERSION;
