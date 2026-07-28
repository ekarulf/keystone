//! Assembling and writing the generated project.
//!
//! [`GeneratedProject::render`] produces the complete file set in memory, which is
//! what `keystone infra cdk print` shows and `keystone infra cdk render` writes to
//! a single stream. Nothing touches the filesystem until [`GeneratedProject::write`].
//!
//! Writing is conservative in two ways the design calls for:
//!
//! * "Do not overwrite modified generated files without `--force`." A file whose
//!   content still matches what Keystone would generate is rewritten silently; a
//!   file the user has edited is left alone and reported.
//! * A `cdk-outputs.json` or `node_modules` already in the output directory is
//!   never touched, because the file set never names them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use keystone_core::error::{KeystoneError, Result};

use crate::plan::CdkPlan;
use crate::template::{self, Renderer};

/// One file to write, with its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    /// Path relative to the output directory, always using `/`.
    pub path: String,
    pub contents: String,
    /// Whether the file is expected to be edited after generation.
    ///
    /// An inline policy or a stack the user extends is theirs; `--force` warns
    /// before replacing one.
    pub user_editable: bool,
}

/// The complete generated project, in memory.
#[derive(Debug, Clone)]
pub struct GeneratedProject {
    pub files: Vec<GeneratedFile>,
    /// What was recorded in the generated metadata, for the CLI to echo.
    pub generated_at: String,
    pub template_version: u32,
    pub generator_version: &'static str,
}

/// What happened to one file during a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The file did not exist and was written.
    Created,
    /// The file existed with different content and was replaced.
    Replaced,
    /// The file existed with exactly this content.
    Unchanged,
    /// The file existed, differed, and `--force` was not given.
    SkippedModified,
}

/// The result of writing a project.
#[derive(Debug, Clone)]
pub struct WriteReport {
    pub root: PathBuf,
    pub outcomes: Vec<(String, WriteOutcome)>,
}

impl WriteReport {
    /// Files left alone because they had been modified.
    pub fn skipped(&self) -> Vec<&str> {
        self.outcomes
            .iter()
            .filter(|(_, outcome)| *outcome == WriteOutcome::SkippedModified)
            .map(|(path, _)| path.as_str())
            .collect()
    }

    /// Whether anything was refused, so the CLI can exit non-zero.
    pub fn has_conflicts(&self) -> bool {
        !self.skipped().is_empty()
    }

    pub fn count(&self, outcome: WriteOutcome) -> usize {
        self.outcomes
            .iter()
            .filter(|(_, found)| *found == outcome)
            .count()
    }
}

impl GeneratedProject {
    /// Render every file for `plan`.
    ///
    /// `generated_at` is passed in rather than read from the clock so the same
    /// plan renders identically in a test and so `print` and `init` agree.
    pub fn render(plan: &CdkPlan, generated_at: time::OffsetDateTime) -> Result<Self> {
        let generated_at = generated_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| {
                KeystoneError::Other(format!("cannot format the generation timestamp: {error}"))
            })?;

        let renderer = Renderer::new()?;
        let context = template::context_for(plan, &generated_at)?;

        let mut files = Vec::new();
        // The entry point is named after the project, which is the CDK convention
        // and what `cdk.json` and `package.json` point at.
        let bin_path = format!("bin/{}.ts", plan.project_slug());
        let lib_path = format!("lib/{}.ts", plan.stack_module());
        let test_path = format!("test/{}.test.ts", plan.stack_module());

        for (template_name, path, user_editable) in [
            ("package.json", "package.json", false),
            ("tsconfig.json", "tsconfig.json", false),
            ("cdk.json", "cdk.json", false),
            ("bin/app.ts", bin_path.as_str(), false),
            ("lib/stack.ts", lib_path.as_str(), true),
            ("test/stack.test.ts", test_path.as_str(), true),
            ("README.md", "README.md", false),
            ("keystone.profile.toml", "keystone.profile.toml", false),
        ] {
            files.push(GeneratedFile {
                path: path.to_string(),
                contents: renderer.render(template_name, &context)?,
                user_editable,
            });
        }

        // The CA certificate is public: it is what the trust anchor publishes.
        if let Some(pem) = plan.ca_certificate_pem() {
            files.push(GeneratedFile {
                path: "certificates/keystone-ca.pem".to_string(),
                contents: normalize_pem(pem),
                user_editable: false,
            });
        }

        if let Some(document) = plan.inline_policy() {
            let mut json = serde_json::to_string_pretty(document).map_err(|error| {
                KeystoneError::Other(format!("cannot serialize the inline policy: {error}"))
            })?;
            json.push('\n');
            files.push(GeneratedFile {
                path: "policy/inline-policy.json".to_string(),
                contents: json,
                user_editable: true,
            });
        }

        files.push(GeneratedFile {
            path: ".gitignore".to_string(),
            contents: GITIGNORE.to_string(),
            user_editable: true,
        });

        let project = Self {
            files,
            generated_at,
            template_version: template::TEMPLATE_VERSION,
            generator_version: template::GENERATOR_VERSION,
        };
        project.assert_no_private_key_material()?;
        Ok(project)
    }

    /// Look up one rendered file.
    pub fn file(&self, path: &str) -> Option<&GeneratedFile> {
        self.files.iter().find(|file| file.path == path)
    }

    /// The files as a map, for `print`.
    pub fn as_map(&self) -> BTreeMap<&str, &str> {
        self.files
            .iter()
            .map(|file| (file.path.as_str(), file.contents.as_str()))
            .collect()
    }

    /// Refuse to emit anything that looks like a private key.
    ///
    /// The design's rule for the generated output is absolute: "The final output
    /// must not contain: `ca-private-key.pem`". Nothing in [`CdkPlan`] carries a
    /// private key, so this cannot fire today — it is here so that a future
    /// template or plan field cannot make it fire silently.
    fn assert_no_private_key_material(&self) -> Result<()> {
        // PEM armor rather than the words "private key": the README explains in
        // prose that no `ca-private-key.pem` exists, and that sentence is part of
        // the deliverable.
        const MARKERS: &[&str] = &["PRIVATE KEY-----", "BEGIN EC PARAMETERS"];
        for file in &self.files {
            if file.path.contains("private-key") || file.path.contains("private_key") {
                return Err(KeystoneError::Other(format!(
                    "refusing to generate {}: a generated CDK project must hold only public \
                     material",
                    file.path
                )));
            }
            for marker in MARKERS {
                if file.contents.contains(marker) {
                    return Err(KeystoneError::Other(format!(
                        "refusing to generate {}: it contains {marker:?}, and a generated CDK \
                         project must hold only public material",
                        file.path
                    )));
                }
            }
        }
        Ok(())
    }

    /// Write the project under `root`.
    ///
    /// Creates directories as needed. Existing files are compared before being
    /// touched, so re-running `init` on an untouched project is a no-op and
    /// re-running it on an edited one reports rather than clobbers.
    pub fn write(&self, root: &Path, force: bool) -> Result<WriteReport> {
        let mut outcomes = Vec::with_capacity(self.files.len());

        for file in &self.files {
            let target = root.join(&file.path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    KeystoneError::io(format!("cannot create {}", parent.display()), error)
                })?;
            }

            let outcome = match read_if_present(&target)? {
                Some(existing) if existing == file.contents => WriteOutcome::Unchanged,
                Some(_) if !force => WriteOutcome::SkippedModified,
                Some(_) => WriteOutcome::Replaced,
                None => WriteOutcome::Created,
            };

            if matches!(outcome, WriteOutcome::Created | WriteOutcome::Replaced) {
                // Atomic, so an interrupted `init` cannot leave a half-written
                // TypeScript file that fails to compile for a confusing reason.
                keystone_core::store::write_atomic(&target, file.contents.as_bytes())?;
            }
            outcomes.push((file.path.clone(), outcome));
        }

        Ok(WriteReport {
            root: root.to_path_buf(),
            outcomes,
        })
    }
}

/// Read a file, treating absence as `None` rather than an error.
fn read_if_present(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(text) => Ok(Some(text)),
            // A non-UTF-8 file at a generated path is certainly not something
            // Keystone wrote, so it counts as modified.
            Err(_) => Ok(Some(String::from("\u{fffd}"))),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(KeystoneError::io(
            format!("cannot read {}", path.display()),
            error,
        )),
    }
}

/// Ensure the PEM ends with exactly one newline.
///
/// CloudFormation is not fussy, but a missing trailing newline makes every
/// subsequent regeneration look like a diff.
fn normalize_pem(pem: &str) -> String {
    let mut normalized = pem.trim_end().to_string();
    normalized.push('\n');
    normalized
}

const GITIGNORE: &str = "\
# Generated by keystone.
node_modules/
cdk.out/
*.d.ts
*.js
!jest.config.js

# `cdk deploy --outputs-file` writes deployed ARNs here. They are not secret, but
# they are environment-specific: keep them out of a shared repository.
cdk-outputs.json
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{PermissionMode, PlanRequest};
    use keystone_core::config::{IssuerMetadata, Profile};
    use keystone_core::identity::KeyId;

    const NOW: time::OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

    fn profile() -> Profile {
        let mut profile = Profile::new("us-east-1");
        profile.key_id = Some(KeyId::parse("01JZKEYSTONEDEVICE00000001").unwrap());
        profile.issuer = Some(IssuerMetadata::ephemeral(NOW + time::Duration::days(365)));
        profile
    }

    fn plan_with(request: PlanRequest) -> CdkPlan {
        CdkPlan::build(
            PlanRequest {
                profile_name: "personal".to_string(),
                ca_certificate_pem: Some(
                    keystone_pki::testing::TestCa::generate().certificate_pem(),
                ),
                ..request
            },
            &profile(),
        )
        .unwrap()
    }

    fn plan() -> CdkPlan {
        plan_with(PlanRequest::default())
    }

    fn project() -> GeneratedProject {
        GeneratedProject::render(&plan(), NOW).unwrap()
    }

    /// A temporary directory that cleans up when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("keystone-infra-{name}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_project_has_the_files_the_design_lists() {
        let project = project();
        let paths: Vec<&str> = project.files.iter().map(|f| f.path.as_str()).collect();
        for expected in [
            "bin/keystone-personal.ts",
            "lib/keystone-personal-stack.ts",
            "test/keystone-personal-stack.test.ts",
            "certificates/keystone-ca.pem",
            "cdk.json",
            "package.json",
            "tsconfig.json",
            "README.md",
            "keystone.profile.toml",
        ] {
            assert!(
                paths.contains(&expected),
                "{expected} missing from {paths:?}"
            );
        }
    }

    #[test]
    fn the_output_never_contains_a_private_key() {
        // The design's rule, checked over every rendered byte rather than by
        // inspection.
        for project in [
            project(),
            GeneratedProject::render(
                &plan_with(PlanRequest {
                    permissions: Some(PermissionMode::inline(r#"{"Statement":[]}"#).unwrap()),
                    ..Default::default()
                }),
                NOW,
            )
            .unwrap(),
        ] {
            for file in &project.files {
                assert!(
                    !file.contents.contains("PRIVATE KEY-----"),
                    "{} contains PEM-armored key material",
                    file.path
                );
                assert!(
                    !file.path.contains("private"),
                    "{} names private material",
                    file.path
                );
            }
        }
    }

    #[test]
    fn the_ca_certificate_is_embedded_as_pem() {
        let project = project();
        let pem = &project
            .file("certificates/keystone-ca.pem")
            .unwrap()
            .contents;
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("\n"));
        assert!(!pem.ends_with("\n\n"));
        // And it parses, so the deployed trust anchor gets a real bundle.
        keystone_pki::ParsedCertificate::from_pem(pem).unwrap();
    }

    #[test]
    fn the_stack_authorizes_this_device_and_nothing_wider() {
        let project = project();
        // The device identity reaches the stack as a prop, so the literal is in the
        // entry point and the condition that uses it is in the stack.
        let bin = &project.file("bin/keystone-personal.ts").unwrap().contents;
        assert!(bin.contains("urn:keystone:device:01JZKEYSTONEDEVICE00000001"));

        let stack = &project
            .file("lib/keystone-personal-stack.ts")
            .unwrap()
            .contents;
        assert!(stack.contains("aws:PrincipalTag/x509SAN/URI"));
        assert!(stack.contains("props.deviceSanUri"));
        assert!(stack.contains("CERTIFICATE_BUNDLE"));
        assert!(stack.contains("rolesanywhere.amazonaws.com"));
        assert!(stack.contains("aws:SourceArn"));
        assert!(stack.contains("aws:SourceAccount"));
        assert!(!stack.contains("AdministratorAccess"));
    }

    #[test]
    fn the_default_stack_attaches_no_policies() {
        let project = project();
        let stack = &project
            .file("lib/keystone-personal-stack.ts")
            .unwrap()
            .contents;
        assert!(!stack.contains("addManagedPolicy"));
        assert!(!stack.contains("attachInlinePolicy"));
        assert!(stack.contains("No workload permissions"));
    }

    #[test]
    fn an_inline_policy_is_written_as_its_own_file_and_referenced() {
        let project = GeneratedProject::render(
            &plan_with(PlanRequest {
                permissions: Some(
                    PermissionMode::inline(
                        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
                    )
                    .unwrap(),
                ),
                ..Default::default()
            }),
            NOW,
        )
        .unwrap();

        let policy = &project.file("policy/inline-policy.json").unwrap().contents;
        assert!(policy.contains("s3:GetObject"));
        // Valid JSON, so `cdk synth` can read it back.
        serde_json::from_str::<serde_json::Value>(policy).unwrap();

        let stack = &project
            .file("lib/keystone-personal-stack.ts")
            .unwrap()
            .contents;
        assert!(stack.contains("attachInlinePolicy"));
        assert!(stack.contains("inline-policy.json"));
    }

    #[test]
    fn managed_policies_are_attached_one_per_arn_with_unique_construct_ids() {
        // Two constructs with the same id is a synth-time error, so the loop index
        // has to reach the generated code.
        let project = GeneratedProject::render(
            &plan_with(PlanRequest {
                permissions: Some(
                    PermissionMode::managed(vec![
                        "arn:aws:iam::aws:policy/ReadOnlyAccess".to_string(),
                        "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess".to_string(),
                    ])
                    .unwrap(),
                ),
                ..Default::default()
            }),
            NOW,
        )
        .unwrap();

        let stack = &project
            .file("lib/keystone-personal-stack.ts")
            .unwrap()
            .contents;
        assert!(stack.contains("KeystoneManagedPolicy0"));
        assert!(stack.contains("KeystoneManagedPolicy1"));
        assert!(stack.contains("ReadOnlyAccess"));
        assert!(stack.contains("AWSXrayWriteOnlyAccess"));
    }

    #[test]
    fn an_existing_role_project_creates_no_role_and_documents_the_trust_policy() {
        let project = GeneratedProject::render(
            &plan_with(PlanRequest {
                existing_role_arn: Some("arn:aws:iam::123456789012:role/Developer".to_string()),
                ..Default::default()
            }),
            NOW,
        )
        .unwrap();

        let stack = &project
            .file("lib/keystone-personal-stack.ts")
            .unwrap()
            .contents;
        assert!(!stack.contains("new iam.Role("));
        assert!(stack.contains("props.existingRoleArn"));
        assert!(project
            .file("bin/keystone-personal.ts")
            .unwrap()
            .contents
            .contains("arn:aws:iam::123456789012:role/Developer"));

        // The design: "The generated README should provide the trust-policy
        // statement that must be added to the existing role."
        let readme = &project.file("README.md").unwrap().contents;
        assert!(readme.contains("Trust policy for the existing role"));
        assert!(readme.contains("sts:AssumeRole"));
        assert!(readme.contains("aws:PrincipalTag/x509SAN/URI"));
    }

    #[test]
    fn an_existing_trust_anchor_project_omits_the_anchor_and_the_certificate() {
        let project = GeneratedProject::render(
            &plan_with(PlanRequest {
                existing_trust_anchor_arn: Some(
                    "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abc".to_string(),
                ),
                ca_certificate_pem: None,
                ..Default::default()
            }),
            NOW,
        )
        .unwrap();

        assert!(project.file("certificates/keystone-ca.pem").is_none());
        let stack = &project
            .file("lib/keystone-personal-stack.ts")
            .unwrap()
            .contents;
        assert!(!stack.contains("CfnTrustAnchor"));
        assert!(stack.contains("props.existingTrustAnchorArn"));
        assert!(project
            .file("bin/keystone-personal.ts")
            .unwrap()
            .contents
            .contains("trust-anchor/abc"));
    }

    #[test]
    fn the_generated_test_file_asserts_the_device_restriction() {
        // The generated tests are part of the deliverable: they are what catches a
        // later edit that weakens the trust policy.
        let project = project();
        let test = &project
            .file("test/keystone-personal-stack.test.ts")
            .unwrap()
            .contents;
        assert!(test.contains("AdministratorAccess"));
        assert!(test.contains("aws:PrincipalTag/x509SAN/URI"));
        assert!(test.contains("AWS::RolesAnywhere::TrustAnchor"));
        assert!(test.contains("AWS::RolesAnywhere::Profile"));
        assert!(test.contains("TrustAnchorArn"));
    }

    #[test]
    fn package_and_cdk_json_are_valid_json_pointing_at_the_generated_entry_point() {
        let project = project();
        let package: serde_json::Value =
            serde_json::from_str(&project.file("package.json").unwrap().contents).unwrap();
        assert_eq!(package["keystone"]["templateVersion"], 1);
        assert_eq!(package["keystone"]["generatedBy"], "keystone");
        assert_eq!(package["keystone"]["profile"], "personal");
        assert_eq!(package["name"], "keystone-personal");

        let cdk: serde_json::Value =
            serde_json::from_str(&project.file("cdk.json").unwrap().contents).unwrap();
        let app = cdk["app"].as_str().unwrap();
        assert!(app.contains("bin/keystone-personal.ts"), "{app}");
        assert!(project.file("bin/keystone-personal.ts").is_some());

        // tsconfig too: a malformed one breaks `cdk synth` with a parse error.
        serde_json::from_str::<serde_json::Value>(&project.file("tsconfig.json").unwrap().contents)
            .unwrap();
    }

    #[test]
    fn the_recorded_profile_toml_parses_and_leaves_arns_as_placeholders() {
        let project = project();
        let text = &project.file("keystone.profile.toml").unwrap().contents;
        let parsed: toml::Value = toml::from_str(text).unwrap();
        let recorded = &parsed["profiles"]["personal"];
        assert_eq!(recorded["region"].as_str(), Some("us-east-1"));
        assert_eq!(
            recorded["role_arn"].as_str(),
            Some(keystone_core::config::PLACEHOLDER)
        );
        assert_eq!(
            recorded["key_id"].as_str(),
            Some("01JZKEYSTONEDEVICE00000001")
        );
        // And no key reference: the file is a public record.
        assert!(!text.contains("opaque"));
    }

    #[test]
    fn writing_creates_every_file_and_a_second_write_changes_nothing() {
        let dir = TempDir::new("write-idempotent");
        let project = project();

        let first = project.write(dir.path(), false).unwrap();
        assert_eq!(first.count(WriteOutcome::Created), project.files.len());
        assert!(!first.has_conflicts());
        assert!(dir.path().join("lib/keystone-personal-stack.ts").is_file());

        // Re-running `init` on an untouched project must not report conflicts:
        // the content matches, so there is nothing to protect.
        let second = project.write(dir.path(), false).unwrap();
        assert_eq!(second.count(WriteOutcome::Unchanged), project.files.len());
        assert!(!second.has_conflicts());
    }

    #[test]
    fn a_modified_file_is_left_alone_without_force() {
        // "Do not overwrite modified generated files without `--force`." Losing a
        // hand-tuned stack to a regeneration would be unrecoverable.
        let dir = TempDir::new("write-modified");
        let project = project();
        project.write(dir.path(), false).unwrap();

        let edited = dir.path().join("lib/keystone-personal-stack.ts");
        std::fs::write(&edited, "// my own stack\n").unwrap();

        let report = project.write(dir.path(), false).unwrap();
        assert_eq!(
            report.skipped(),
            vec!["lib/keystone-personal-stack.ts"],
            "only the edited file should be skipped"
        );
        assert!(report.has_conflicts());
        assert_eq!(
            std::fs::read_to_string(&edited).unwrap(),
            "// my own stack\n",
            "the edit was overwritten"
        );

        let forced = project.write(dir.path(), true).unwrap();
        assert!(!forced.has_conflicts());
        assert_eq!(forced.count(WriteOutcome::Replaced), 1);
        assert!(std::fs::read_to_string(&edited)
            .unwrap()
            .contains("CfnTrustAnchor"));
    }

    #[test]
    fn writing_does_not_touch_files_the_project_does_not_name() {
        // `cdk deploy --outputs-file` and `npm install` leave things in this
        // directory; regenerating must not disturb them.
        let dir = TempDir::new("write-foreign");
        let project = project();
        project.write(dir.path(), false).unwrap();

        let outputs = dir.path().join("cdk-outputs.json");
        std::fs::write(&outputs, "{\"KeystonePersonal\":{}}").unwrap();
        std::fs::create_dir_all(dir.path().join("node_modules/aws-cdk-lib")).unwrap();

        project.write(dir.path(), true).unwrap();
        assert!(outputs.is_file());
        assert!(dir.path().join("node_modules/aws-cdk-lib").is_dir());
    }

    #[test]
    fn the_gitignore_excludes_the_deployed_outputs_file() {
        let project = project();
        let ignore = &project.file(".gitignore").unwrap().contents;
        assert!(ignore.contains("cdk-outputs.json"));
        assert!(ignore.contains("node_modules/"));
    }

    #[test]
    fn generated_files_record_the_generator_and_template_version() {
        // The design's generated metadata. Without it there is no way to tell
        // which template version produced a project that needs regenerating.
        let project = project();
        assert_eq!(project.template_version, 1);
        assert_eq!(project.generated_at, "2026-07-26T01:15:00Z");
        for path in [
            "README.md",
            "lib/keystone-personal-stack.ts",
            "package.json",
        ] {
            let contents = &project.file(path).unwrap().contents;
            assert!(
                contents.contains(project.generator_version),
                "{path} does not record the generator version"
            );
        }
    }

    #[test]
    fn generated_typescript_keeps_its_indentation_through_every_branch() {
        // Tera's `{% if x -%}` trims the newline *and* the following line's leading
        // whitespace, which silently flattens the first line of a conditional block
        // to column 0. The result still compiles, so only a check like this catches
        // it. Every branch of every conditional is exercised, because the trim
        // affects each independently.
        let variants: Vec<(&str, PlanRequest)> = vec![
            ("default", PlanRequest::default()),
            (
                "inline policy",
                PlanRequest {
                    permissions: Some(PermissionMode::Inline {
                        document: serde_json::json!({"Version": "2012-10-17", "Statement": []}),
                    }),
                    ..Default::default()
                },
            ),
            (
                "managed policies",
                PlanRequest {
                    permissions: Some(PermissionMode::Managed {
                        arns: vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()],
                    }),
                    ..Default::default()
                },
            ),
            (
                "existing role",
                PlanRequest {
                    existing_role_arn: Some("arn:aws:iam::123456789012:role/Existing".to_string()),
                    ..Default::default()
                },
            ),
            (
                "existing trust anchor",
                PlanRequest {
                    existing_trust_anchor_arn: Some(
                        "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/abcd"
                            .to_string(),
                    ),
                    ..Default::default()
                },
            ),
        ];

        for (label, request) in variants {
            let project = GeneratedProject::render(&plan_with(request), NOW).unwrap();
            let stack = &project
                .file("lib/keystone-personal-stack.ts")
                .unwrap()
                .contents;
            // Everything inside the class body is indented at least two spaces. The
            // file header comment is the only content legitimately at column 0, and
            // it ends at the first `import`.
            let body = stack
                .split_once("\nimport ")
                .map(|(_, rest)| rest)
                .unwrap_or(stack);
            for line in body.lines() {
                let trimmed = line.trim_start();
                if trimmed.is_empty() || !line.starts_with(char::is_alphabetic) {
                    continue;
                }
                assert!(
                    trimmed.starts_with("export ")
                        || trimmed.starts_with("import ")
                        || trimmed.starts_with('}'),
                    "{label}: {line:?} lost its indentation"
                );
            }
        }
    }

    #[test]
    fn a_stack_name_needing_escaping_still_produces_parseable_typescript() {
        // Names reach generated TypeScript as string literals. A quote or
        // backslash that is not escaped produces a file that does not compile —
        // and the `json_encode` filter is what prevents it.
        let mut request = PlanRequest {
            profile_name: "personal".to_string(),
            ca_certificate_pem: Some(keystone_pki::testing::TestCa::generate().certificate_pem()),
            ..Default::default()
        };
        // Legal for IAM, awkward for a string literal.
        request.role_name = Some("Keystone.Personal@Mac".to_string());
        let plan = CdkPlan::build(request, &profile()).unwrap();
        let project = GeneratedProject::render(&plan, NOW).unwrap();
        let bin = &project.file("bin/keystone-personal.ts").unwrap().contents;
        assert!(bin.contains("\"Keystone.Personal@Mac\""), "{bin}");
    }
}
