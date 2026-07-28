//! The embedded CDK templates and the engine that renders them.
//!
//! Templates are compiled into the binary with `include_str!`, so `keystone infra
//! cdk init` works from a single downloaded executable with no template directory
//! to find, and the templates cannot be swapped out under it by another local
//! user.
//!
//! The template set is versioned as a whole ([`TEMPLATE_VERSION`]). A change that
//! alters generated output belongs in a new `cdk-typescript-vN` directory rather
//! than in this one, so a regenerated project can be diffed against the version
//! it was first generated from.

use keystone_core::error::{KeystoneError, Result};
use tera::{Context, Tera};

use crate::plan::{CdkPlan, PermissionMode, RoleTarget, TrustAnchorTarget};

/// The version of the embedded template set.
pub const TEMPLATE_VERSION: u32 = 1;

/// The Keystone version recorded in generated files.
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The directory the templates came from, for generated metadata and diagnostics.
pub const TEMPLATE_SET: &str = "cdk-typescript-v1";

/// Embed one template from the versioned set.
///
/// `include_str!` needs a literal path, so the directory name appears here rather
/// than being taken from [`TEMPLATE_SET`]; a new template version means a new
/// module, and this macro's path changes with it.
macro_rules! template_source {
    ($file:literal) => {
        include_str!(concat!("../../../templates/cdk-typescript-v1/", $file))
    };
}

/// Render a template by name against a plan.
pub struct Renderer {
    tera: Tera,
}

impl Renderer {
    /// Build an engine with the embedded templates registered.
    pub fn new() -> Result<Self> {
        let mut tera = Tera::default();
        register_filters(&mut tera);
        tera.add_raw_templates(sources())
            .map_err(|error| template_error("registering the embedded templates", &error))?;
        Ok(Self { tera })
    }

    /// Render one template.
    pub fn render(&self, name: &str, context: &Context) -> Result<String> {
        self.tera
            .render(name, context)
            .map_err(|error| template_error(&format!("rendering {name}"), &error))
    }

    /// The registered template names.
    pub fn names(&self) -> Vec<String> {
        self.tera.get_template_names().map(String::from).collect()
    }
}

/// The templates, as (name, source) pairs.
fn sources() -> Vec<(&'static str, &'static str)> {
    vec![
        ("package.json", template_source!("package.json.tera")),
        ("tsconfig.json", template_source!("tsconfig.json.tera")),
        ("cdk.json", template_source!("cdk.json.tera")),
        ("bin/app.ts", template_source!("bin/app.ts.tera")),
        ("lib/stack.ts", template_source!("lib/stack.ts.tera")),
        (
            "test/stack.test.ts",
            template_source!("test/stack.test.ts.tera"),
        ),
        ("README.md", template_source!("README.md.tera")),
        (
            "keystone.profile.toml",
            template_source!("keystone.profile.toml.tera"),
        ),
    ]
}

/// Register the filters the templates use.
///
/// Tera 2 dropped `json_encode`, and the templates need it for every value that
/// lands inside generated TypeScript: a stack name with an apostrophe or a
/// backslash would otherwise produce a file that does not parse, and in the worst
/// case a value that closes the string literal and continues as code.
fn register_filters(tera: &mut Tera) {
    tera.register_filter(
        "json_encode",
        |value: &tera::Value, _: tera::Kwargs, _: &tera::State| -> tera::TeraResult<tera::Value> {
            let json = serde_json::to_string(value)
                .map_err(|error| tera::Error::message(format!("cannot JSON-encode: {error}")))?;
            Ok(tera::Value::from(json))
        },
    );
}

/// Turn a Tera error into a Keystone one, keeping the chain.
///
/// Tera reports the useful part — which template, which line — in the source
/// chain rather than the top-level message, so flattening it loses exactly the
/// detail needed to fix a template.
fn template_error(what: &str, error: &tera::Error) -> KeystoneError {
    let mut message = format!("{what} failed: {error}");
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    KeystoneError::Other(message)
}

/// Build the rendering context from a plan.
///
/// One function, so every template sees the same variable names and a template
/// cannot silently read an undefined value.
pub fn context_for(plan: &CdkPlan, generated_at: &str) -> Result<Context> {
    let mut context = Context::new();

    context.insert("generator_version", &GENERATOR_VERSION);
    context.insert("template_version", &TEMPLATE_VERSION);
    context.insert("generated_at", &generated_at);
    context.insert("placeholder", &keystone_core::config::PLACEHOLDER);

    context.insert("profile_name", &plan.profile_name);
    context.insert("region", &plan.region);
    context.insert("stack_name", &plan.stack_name);
    context.insert("stack_class", &plan.stack_class());
    context.insert("stack_module", &plan.stack_module());
    context.insert("project_slug", &plan.project_slug());
    context.insert("bin_entry", &format!("bin/{}.ts", plan.project_slug()));
    context.insert("trust_anchor_name", &plan.trust_anchor_name);
    context.insert(
        "roles_anywhere_profile_name",
        &plan.roles_anywhere_profile_name,
    );
    context.insert("duration_seconds", &plan.duration_seconds);
    context.insert("key_id", &plan.key_id.as_str());
    context.insert("device_san_uri", &plan.device_san_uri());
    context.insert("role_session_name", &plan.role_session_name);
    context.insert("issuer_mode", &plan.issuer_mode);
    context.insert(
        "certificate_fingerprint",
        &plan
            .certificate_fingerprint
            .as_ref()
            .map(|f| f.as_str().to_string()),
    );
    context.insert(
        "ca_fingerprint",
        &plan.ca_fingerprint.as_ref().map(|f| f.as_str().to_string()),
    );
    context.insert(
        "certificate_expires_at",
        &plan
            .certificate_expires_at
            .map(format_timestamp)
            .transpose()?,
    );

    match &plan.trust_anchor {
        TrustAnchorTarget::Existing { arn } => {
            context.insert("existing_trust_anchor_arn", arn);
        }
        TrustAnchorTarget::Create { .. } => {
            // Absent rather than empty: the templates branch on `{% if %}`, and an
            // empty string is falsy in Tera but an easy thing to get wrong.
            context.insert("existing_trust_anchor_arn", &None::<String>);
        }
    }

    match &plan.role {
        RoleTarget::Existing { arn } => {
            context.insert("existing_role_arn", arn);
            context.insert("role_name", &None::<String>);
            context.insert("permissions", &"existing");
            context.insert("managed_policy_arns", &Vec::<String>::new());
        }
        RoleTarget::Create { name, permissions } => {
            context.insert("existing_role_arn", &None::<String>);
            context.insert("role_name", name);
            context.insert("permissions", &permissions.as_str());
            context.insert(
                "managed_policy_arns",
                match permissions {
                    PermissionMode::Managed { arns } => arns.as_slice(),
                    _ => &[],
                },
            );
        }
    }

    Ok(context)
}

/// RFC 3339, which is what the design's generated metadata shows.
fn format_timestamp(at: time::OffsetDateTime) -> Result<String> {
    at.format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| KeystoneError::Other(format!("cannot format a timestamp: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_in_the_set_is_registered_and_parses() {
        // A template with a syntax error would otherwise surface only when a user
        // happens to generate a project that renders it.
        let renderer = Renderer::new().unwrap();
        let mut names = renderer.names();
        names.sort();
        assert_eq!(
            names,
            vec![
                "README.md",
                "bin/app.ts",
                "cdk.json",
                "keystone.profile.toml",
                "lib/stack.ts",
                "package.json",
                "test/stack.test.ts",
                "tsconfig.json",
            ]
        );
    }

    #[test]
    fn json_encode_quotes_and_escapes() {
        // The filter that keeps a hostile or merely awkward name from breaking out
        // of a TypeScript string literal.
        let mut tera = Tera::default();
        register_filters(&mut tera);
        tera.add_raw_template("t", "{{ value | json_encode }}")
            .unwrap();
        for (input, expected) in [
            ("plain", "\"plain\""),
            ("with \"quotes\"", "\"with \\\"quotes\\\"\""),
            ("back\\slash", "\"back\\\\slash\""),
            ("new\nline", "\"new\\nline\""),
            ("\"; process.exit(1); //", "\"\\\"; process.exit(1); //\""),
        ] {
            let mut context = Context::new();
            context.insert("value", &input);
            assert_eq!(tera.render("t", &context).unwrap(), expected, "{input:?}");
        }
    }
}
