//! CDK tests against generated projects and a real `cdk synth`.
//!
//! The design's CDK test list:
//!
//! * synth succeeds;
//! * expected resources exist;
//! * external CA bundle is embedded correctly;
//! * IAM role has no default admin policy;
//! * SAN restriction is present;
//! * outputs have expected names;
//! * `sync-profile` handles conflicts safely.
//!
//! The first four are only fully answered by CloudFormation: a template is what
//! AWS acts on, and a condition that looks right in TypeScript can synthesize to
//! nothing. So those checks appear twice here, at two strengths.
//!
//! The source-level checks run in the default suite. They are cheap and they
//! catch the regressions that matter most — a lost `Effect.DENY`, an
//! `AdministratorAccess` that crept into a template.
//!
//! The synth-level checks run `npm install` and the CDK CLI, so they are
//! `#[ignore]`d: they need a network and a few minutes. Run them with
//!
//! ```text
//! cargo test -p keystone-tests --test integration_cdk -- --ignored --nocapture
//! ```
//!
//! before releasing a template change, which is the only time the generated
//! TypeScript can break.
//!
//! `sync-profile` is exercised end to end from a `cdk-outputs.json` of the shape
//! `cdk deploy --outputs-file` writes. `keystone-infra`'s unit tests cover the
//! same rules from constructed `StackOutputs` values; these cover the parsing and
//! the file handling as well.

use keystone_core::config::{Paths, Profile};
use keystone_core::identity::KeyId;
use keystone_core::store::Store;
use keystone_infra::outputs::StackOutputs;
use keystone_infra::plan::{CdkPlan, PermissionMode, PlanRequest};
use keystone_infra::project::GeneratedProject;
use keystone_infra::sync::sync_profile;
use keystone_tests::{fixture, TempDir};
use time::OffsetDateTime;

const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);
const KEY_ID: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
const DEVICE_SAN: &str = "urn:keystone:device:0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The generated file names, which follow from the default stack name
/// `KeystonePersonal`.
const STACK_PATH: &str = "lib/keystone-personal-stack.ts";
const APP_PATH: &str = "bin/keystone-personal.ts";
const CA_PATH: &str = "certificates/keystone-ca.pem";

fn profile() -> Profile {
    let mut profile = Profile::new("us-east-1");
    profile.key_id = Some(KeyId::parse(KEY_ID).unwrap());
    profile.issuer = Some(keystone_core::config::IssuerMetadata::ephemeral(
        NOW + time::Duration::days(365),
    ));
    profile
}

/// A plan for the `personal` profile, with the OpenSSL fixture CA as the anchor.
///
/// The CA comes from `tests/fixtures/generate.sh` rather than from
/// `keystone-pki`, so what is embedded in the template is a certificate an
/// independent tool produced.
fn plan_with(request: PlanRequest) -> CdkPlan {
    CdkPlan::build(
        PlanRequest {
            profile_name: "personal".to_string(),
            ca_certificate_pem: request
                .ca_certificate_pem
                .clone()
                .or_else(|| Some(fixture("ca.pem"))),
            ..request
        },
        &profile(),
    )
    .expect("the plan builds")
}

fn project_for(request: PlanRequest) -> GeneratedProject {
    GeneratedProject::render(&plan_with(request), NOW).expect("the project renders")
}

fn source(project: &GeneratedProject, path: &str) -> String {
    project
        .file(path)
        .unwrap_or_else(|| {
            let available: Vec<&str> = project.files.iter().map(|f| f.path.as_str()).collect();
            panic!("the project has no {path}; it has {available:?}")
        })
        .contents
        .clone()
}

// -- Source-level checks ----------------------------------------------------

#[test]
fn the_external_ca_bundle_is_embedded_byte_for_byte() {
    let project = project_for(PlanRequest::default());
    let embedded = source(&project, CA_PATH);
    let expected = fixture("ca.pem");

    // Normalized to a single trailing newline and otherwise identical. The trust
    // anchor is built from these exact bytes; a re-encoded certificate would be a
    // different anchor and would reject this device.
    assert_eq!(embedded.trim_end(), expected.trim_end());
    assert!(embedded.ends_with('\n'));
    assert!(!embedded.ends_with("\n\n"));

    // It must be the CA and not the device certificate. A trust anchor built from
    // the leaf would deploy and then refuse every session.
    let parsed = keystone_pki::ParsedCertificate::from_pem(&embedded).expect("the bundle parses");
    assert!(parsed.is_ca);
    assert!(
        parsed.subject.contains("Keystone Ephemeral CA"),
        "{}",
        parsed.subject
    );

    // And the stack reads that file rather than inlining the PEM, so rotating the
    // anchor is a one-file change.
    let stack = source(&project, STACK_PATH);
    assert!(
        stack.contains(r#""certificates", "keystone-ca.pem""#),
        "the stack does not read the certificate file:\n{stack}"
    );
    assert!(
        !stack.contains("BEGIN CERTIFICATE"),
        "the PEM is inlined in the stack source"
    );
}

#[test]
fn no_ca_certificate_file_is_generated_when_an_existing_anchor_is_reused() {
    // Writing a bundle nothing reads would invite someone to point a hand-written
    // anchor at a stale certificate.
    let project = project_for(PlanRequest {
        existing_trust_anchor_arn: Some(
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/tttt".to_string(),
        ),
        ..Default::default()
    });
    assert!(project.file(CA_PATH).is_none());
    let stack = source(&project, STACK_PATH);
    assert!(!stack.contains("CfnTrustAnchor("), "{stack}");
    assert!(stack.contains("props.existingTrustAnchorArn"), "{stack}");
}

#[test]
fn no_generated_file_holds_private_key_material() {
    // "The final output must not contain: ca-private-key.pem." `render` enforces
    // this itself; this checks it across every mode, including the ones that write
    // extra files.
    let requests = vec![
        PlanRequest::default(),
        PlanRequest {
            permissions: Some(
                PermissionMode::inline(r#"{"Version":"2012-10-17","Statement":[]}"#).unwrap(),
            ),
            ..Default::default()
        },
        PlanRequest {
            permissions: Some(
                PermissionMode::managed(vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()])
                    .unwrap(),
            ),
            ..Default::default()
        },
        PlanRequest {
            existing_role_arn: Some("arn:aws:iam::123456789012:role/Elsewhere".to_string()),
            ..Default::default()
        },
    ];

    for request in requests {
        let project = project_for(request);
        for file in &project.files {
            assert!(
                !file.contents.contains("PRIVATE KEY-----"),
                "{} holds private key material",
                file.path
            );
            assert!(
                !file.path.contains("private-key") && !file.path.contains("private_key"),
                "{} is named like a private key",
                file.path
            );
        }
    }
}

#[test]
fn the_generated_role_has_no_administrator_or_wildcard_permissions() {
    // "The generated role must not default to administrator permissions."
    let project = project_for(PlanRequest::default());
    let stack = source(&project, STACK_PATH);
    assert!(!stack.contains("AdministratorAccess"), "{stack}");
    assert!(!stack.contains("PowerUserAccess"), "{stack}");
    assert!(!stack.contains("addManagedPolicy"), "{stack}");
    assert!(!stack.contains("attachInlinePolicy"), "{stack}");
    assert!(!stack.contains(r#"actions: ["*"]"#), "{stack}");

    // The default is explicitly no workload permissions, and the source says so
    // where someone editing it will read it.
    assert!(stack.contains("No workload permissions"), "{stack}");
    assert!(project.file("policy/inline-policy.json").is_none());
}

#[test]
fn requested_permissions_appear_and_nothing_else_does() {
    let inline = project_for(PlanRequest {
        permissions: Some(
            PermissionMode::inline(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#,
            )
            .unwrap(),
        ),
        ..Default::default()
    });
    let policy = source(&inline, "policy/inline-policy.json");
    assert!(policy.contains("s3:ListAllMyBuckets"), "{policy}");
    assert!(policy.ends_with('\n'));
    let stack = source(&inline, STACK_PATH);
    assert!(stack.contains("attachInlinePolicy"), "{stack}");
    assert!(!stack.contains("addManagedPolicy"), "{stack}");

    let managed = project_for(PlanRequest {
        permissions: Some(
            PermissionMode::managed(vec![
                "arn:aws:iam::aws:policy/ReadOnlyAccess".to_string(),
                "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess".to_string(),
            ])
            .unwrap(),
        ),
        ..Default::default()
    });
    let stack = source(&managed, STACK_PATH);
    assert_eq!(
        stack.matches("addManagedPolicy").count(),
        2,
        "one call per requested policy:\n{stack}"
    );
    assert!(stack.contains("ReadOnlyAccess"), "{stack}");
    assert!(!stack.contains("attachInlinePolicy"), "{stack}");
    assert!(managed.file("policy/inline-policy.json").is_none());
}

#[test]
fn the_san_restriction_is_present_and_reaches_the_trust_policy() {
    let project = project_for(PlanRequest::default());
    let stack = source(&project, STACK_PATH);

    // The deny statement, and the tag it tests.
    assert!(stack.contains("iam.Effect.DENY"), "{stack}");
    assert!(stack.contains("StringNotEquals"), "{stack}");
    assert!(stack.contains("aws:PrincipalTag/x509SAN/URI"), "{stack}");
    assert!(stack.contains("props.deviceSanUri"), "{stack}");

    // The attribute mapping that produces that tag. Without it the condition
    // compares against nothing and the restriction is silently inert, which is the
    // failure this pair of assertions exists to catch.
    assert!(stack.contains(r#"certificateField: "x509SAN""#), "{stack}");
    assert!(stack.contains(r#"specifier: "URI""#), "{stack}");

    // And the anchor and account bindings, which stop another trust anchor in the
    // same account from assuming the role.
    assert!(stack.contains("aws:SourceArn"), "{stack}");
    assert!(stack.contains("aws:SourceAccount"), "{stack}");

    // The app passes this device's SAN, derived from the profile's key.
    let app = source(&project, APP_PATH);
    assert!(
        app.contains(DEVICE_SAN),
        "the app must pass the device SAN:\n{app}"
    );
    assert_eq!(
        plan_with(PlanRequest::default()).device_san_uri(),
        DEVICE_SAN
    );
}

#[test]
fn the_trust_policy_allows_the_session_tagging_roles_anywhere_performs() {
    // Found by deploying: `assumedBy` grants only `sts:AssumeRole`, but because the
    // profile maps the URI SAN into a session tag and accepts a role session name,
    // Roles Anywhere also calls `sts:TagSession` and `sts:SetSourceIdentity`.
    // Without them `CreateSession` returns AccessDenied with "Unable to assume
    // role" — *after* accepting the certificate and signature, so it presents as a
    // signing bug. CloudTrail is what distinguishes the two: `algorithmMismatch`
    // and `missingSignedHeaders` are both empty when the signature was fine.
    let stack = source(&project_for(PlanRequest::default()), STACK_PATH);

    let allow = stack
        .split("iam.Effect.DENY")
        .next()
        .expect("the allow statements precede the deny");
    for action in ["sts:TagSession", "sts:SetSourceIdentity"] {
        assert!(
            allow.contains(action),
            "the trust policy must allow {action}:\n{stack}"
        );
    }
}

#[test]
fn the_expected_resources_are_declared() {
    let stack = source(&project_for(PlanRequest::default()), STACK_PATH);
    for resource in [
        "rolesanywhere.CfnTrustAnchor",
        "rolesanywhere.CfnProfile",
        "iam.Role",
    ] {
        assert!(stack.contains(resource), "missing {resource}:\n{stack}");
    }
}

/// The output names the generated stack declares, scraped from its source.
fn declared_outputs(stack_source: &str) -> Vec<String> {
    stack_source
        .split("new CfnOutput(this, \"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next().map(str::to_string))
        .collect()
}

#[test]
fn the_outputs_have_the_expected_names_in_both_directions() {
    // Two failure modes, one test. If the stack drops or renames an output,
    // `sync-profile` fails with a confusing error; if the stack adds one, nobody
    // has decided whether Keystone should read it.
    let stack = source(&project_for(PlanRequest::default()), STACK_PATH);
    let declared = declared_outputs(&stack);
    assert!(!declared.is_empty(), "no outputs found in:\n{stack}");

    // Required by `StackOutputs::parse`.
    for required in ["TrustAnchorArn", "RolesAnywhereProfileArn", "RoleArn"] {
        assert!(
            declared.iter().any(|name| name == required),
            "the stack does not declare {required}: {declared:?}"
        );
    }
    // Read when present.
    for optional in ["Region", "KeystoneKeyId"] {
        assert!(
            declared.iter().any(|name| name == optional),
            "the stack does not declare {optional}: {declared:?}"
        );
    }
    // Declared for the operator's benefit rather than read by Keystone.
    for name in &declared {
        let known = [
            "TrustAnchorArn",
            "RolesAnywhereProfileArn",
            "RoleArn",
            "Region",
            "KeystoneKeyId",
            "DeviceSanUri",
        ]
        .contains(&name.as_str());
        assert!(
            known,
            "the stack declares an output nothing accounts for: {name}"
        );
    }

    // The existing-anchor variant must still emit TrustAnchorArn, since
    // `sync-profile` requires it either way.
    let reused = source(
        &project_for(PlanRequest {
            existing_trust_anchor_arn: Some(
                "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/tttt".to_string(),
            ),
            ..Default::default()
        }),
        STACK_PATH,
    );
    assert!(declared_outputs(&reused).contains(&"TrustAnchorArn".to_string()));
}

#[test]
fn an_externally_managed_role_is_referenced_and_never_modified() {
    // "It does not automatically modify an externally managed role."
    let project = project_for(PlanRequest {
        existing_role_arn: Some("arn:aws:iam::123456789012:role/ManagedElsewhere".to_string()),
        ..Default::default()
    });
    let stack = source(&project, STACK_PATH);
    assert!(!stack.contains("new iam.Role("), "{stack}");
    assert!(!stack.contains("addManagedPolicy"), "{stack}");
    assert!(!stack.contains("attachInlinePolicy"), "{stack}");
    assert!(!stack.contains("assumeRolePolicy"), "{stack}");
    assert!(stack.contains("props.existingRoleArn"), "{stack}");

    // Because the stack cannot add the trust policy itself, the README must print
    // what to add by hand — otherwise the deployment appears to succeed and every
    // `CreateSession` fails.
    let readme = source(&project, "README.md");
    assert!(readme.contains("trust policy"), "{readme}");
    assert!(readme.contains("TRUST_ANCHOR_ARN"), "{readme}");
    assert!(readme.contains("ManagedElsewhere"), "{readme}");
    assert!(
        readme.contains("aws:PrincipalTag/x509SAN/URI"),
        "the hand-written statement must carry the device restriction too:\n{readme}"
    );
}

#[test]
fn permissions_cannot_be_requested_for_a_role_the_stack_does_not_own() {
    // Refused at plan time rather than generated and ignored.
    let error = CdkPlan::build(
        PlanRequest {
            profile_name: "personal".to_string(),
            ca_certificate_pem: Some(fixture("ca.pem")),
            existing_role_arn: Some("arn:aws:iam::123456789012:role/Elsewhere".to_string()),
            permissions: Some(
                PermissionMode::managed(vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".to_string()])
                    .unwrap(),
            ),
            ..Default::default()
        },
        &profile(),
    )
    .expect_err("permissions plus an existing role is a contradiction");
    assert!(format!("{error}").contains("does not modify"), "{error}");
}

#[test]
fn the_generated_project_never_deploys_itself() {
    // "Keystone source generation must not automatically run `cdk deploy`."
    // Nothing generated may invoke deploy as part of build, test, or synth.
    let project = project_for(PlanRequest::default());
    let package = source(&project, "package.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&package).expect("package.json is valid JSON");
    for (name, command) in manifest["scripts"].as_object().expect("scripts") {
        let command = command.as_str().unwrap_or_default();
        assert!(
            !command.contains("deploy"),
            "the {name} script runs a deploy: {command}"
        );
    }
    assert!(!source(&project, "cdk.json").contains("deploy"));

    // The app comment tells the operator to run it, which is the intended path.
    assert!(source(&project, APP_PATH).contains("cdk deploy --outputs-file"));
}

// -- Writing the project ----------------------------------------------------

#[test]
fn a_modified_generated_file_is_not_overwritten_without_force() {
    // "Do not overwrite modified generated files without `--force`." The stack is
    // the file users edit to add permissions, so clobbering it would discard their
    // work.
    let scratch = TempDir::new("cdk-write");
    let root = scratch.join("project");
    let project = project_for(PlanRequest::default());

    project
        .write(&root, false)
        .expect("the first write succeeds");
    let stack_path = root.join(STACK_PATH);
    let edited = format!(
        "{}\n// a local edit\n",
        std::fs::read_to_string(&stack_path).expect("the stack was written")
    );
    std::fs::write(&stack_path, &edited).expect("the edit is applied");

    let report = project
        .write(&root, false)
        .expect("the second write reports");
    assert!(report.has_conflicts());
    assert!(
        report.skipped().contains(&STACK_PATH),
        "{:?}",
        report.skipped()
    );
    assert_eq!(
        std::fs::read_to_string(&stack_path).unwrap(),
        edited,
        "the edit must survive"
    );

    // And `--force` replaces it.
    project.write(&root, true).expect("a forced write succeeds");
    assert_ne!(std::fs::read_to_string(&stack_path).unwrap(), edited);
}

// -- `sync-profile` end to end ----------------------------------------------

const TRUST_ANCHOR: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/1111";
const RA_PROFILE: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/2222";
const ROLE: &str = "arn:aws:iam::123456789012:role/ExampleDeviceRole";

/// An outputs file of the shape `cdk deploy --outputs-file` writes.
fn outputs_json(stack: &str, trust_anchor: &str, role: &str) -> String {
    serde_json::json!({
        stack: {
            "TrustAnchorArn": trust_anchor,
            "RolesAnywhereProfileArn": RA_PROFILE,
            "RoleArn": role,
            "Region": "us-east-1",
            "KeystoneKeyId": KEY_ID,
            "DeviceSanUri": DEVICE_SAN,
        }
    })
    .to_string()
}

/// A store holding one `personal` profile with placeholder ARNs.
fn store_with_fresh_profile(scratch: &TempDir) -> Store {
    let store = Store::new(Paths::rooted_at(scratch.path()));
    let mut config = store.load_config().expect("a default config loads");
    config.profiles.insert("personal".to_string(), profile());
    store.save_config(&config).expect("the config saves");
    store
}

fn write_outputs(scratch: &TempDir, contents: &str) -> std::path::PathBuf {
    let path = scratch.join("cdk-outputs.json");
    std::fs::write(&path, contents).expect("the outputs file writes");
    path
}

#[test]
fn sync_profile_fills_placeholders_from_a_real_outputs_file() {
    let scratch = TempDir::new("sync-fill");
    let store = store_with_fresh_profile(&scratch);
    let path = write_outputs(
        &scratch,
        &outputs_json("KeystonePersonal", TRUST_ANCHOR, ROLE),
    );

    let outputs = StackOutputs::read(&path, None).expect("the outputs file parses");
    assert_eq!(outputs.stack_name, "KeystonePersonal");

    let report = sync_profile(&store, "personal", &outputs, false).expect("sync succeeds");
    assert!(report.saved);
    assert!(report.changed());
    assert!(!report.has_conflicts());

    let config = store.load_config().expect("the config reloads");
    let synced = config.profile("personal").expect("the profile survives");
    assert_eq!(synced.trust_anchor_arn, TRUST_ANCHOR);
    assert_eq!(synced.role_arn, ROLE);
    // The point of the whole exercise: the profile can now request credentials.
    synced
        .require_ready("personal")
        .expect("the profile is usable after sync");
}

#[test]
fn sync_profile_refuses_a_conflicting_arn_and_leaves_the_file_untouched() {
    // "Reject conflicting existing values; require `--force` to overwrite
    // conflicts." A silent overwrite would repoint a working profile at another
    // account's role, and the failure would surface much later as an authorization
    // error.
    let scratch = TempDir::new("sync-conflict");
    let store = store_with_fresh_profile(&scratch);

    let first = write_outputs(
        &scratch,
        &outputs_json("KeystonePersonal", TRUST_ANCHOR, ROLE),
    );
    sync_profile(
        &store,
        "personal",
        &StackOutputs::read(&first, None).unwrap(),
        false,
    )
    .expect("the first sync succeeds");

    let config_path = store.paths().config_file();
    let before = std::fs::read_to_string(&config_path).expect("the config is readable");

    let second = write_outputs(
        &scratch,
        &outputs_json(
            "KeystonePersonal",
            TRUST_ANCHOR,
            "arn:aws:iam::999999999999:role/SomeoneElse",
        ),
    );
    let report = sync_profile(
        &store,
        "personal",
        &StackOutputs::read(&second, None).unwrap(),
        false,
    )
    .expect("a conflict is reported, not an error");

    assert!(report.has_conflicts());
    assert!(!report.saved);
    assert_eq!(report.conflicts().len(), 1);
    assert_eq!(report.conflicts()[0].0, "role_arn");
    assert_eq!(
        std::fs::read_to_string(&config_path).unwrap(),
        before,
        "a refused sync must not modify the configuration file at all"
    );
}

#[test]
fn sync_profile_is_a_no_op_for_a_second_identical_deploy() {
    // "Preserve matching values." Re-running after a no-op `cdk deploy` is routine.
    let scratch = TempDir::new("sync-twice");
    let store = store_with_fresh_profile(&scratch);
    let path = write_outputs(
        &scratch,
        &outputs_json("KeystonePersonal", TRUST_ANCHOR, ROLE),
    );
    let outputs = StackOutputs::read(&path, None).expect("parses");

    sync_profile(&store, "personal", &outputs, false).expect("the first sync succeeds");
    let config_path = store.paths().config_file();
    let after_first = std::fs::read_to_string(&config_path).unwrap();

    let report = sync_profile(&store, "personal", &outputs, false).expect("the second sync runs");
    assert!(!report.changed(), "the second sync should change nothing");
    assert!(!report.saved);
    assert_eq!(std::fs::read_to_string(&config_path).unwrap(), after_first);
}

#[test]
fn sync_profile_refuses_outputs_from_another_devices_stack() {
    // The deployed trust policy authorizes a URI SAN this profile's key does not
    // present, so a "successful" sync would produce a profile that fails every
    // CreateSession. `--force` is for conflicting ARNs, not for the wrong device.
    let scratch = TempDir::new("sync-wrong-device");
    let store = store_with_fresh_profile(&scratch);
    let other_key = "ffffffffffffffffffffffffffffffff";
    let path = write_outputs(
        &scratch,
        &serde_json::json!({
            "KeystoneOther": {
                "TrustAnchorArn": TRUST_ANCHOR,
                "RolesAnywhereProfileArn": RA_PROFILE,
                "RoleArn": ROLE,
                "Region": "us-east-1",
                "KeystoneKeyId": other_key,
            }
        })
        .to_string(),
    );
    let outputs = StackOutputs::read(&path, None).expect("parses");

    for force in [false, true] {
        let error = sync_profile(&store, "personal", &outputs, force)
            .expect_err("the wrong device is refused")
            .to_string();
        assert!(error.contains(other_key), "{error}");
        assert!(error.contains(KEY_ID), "{error}");
    }
}

#[test]
fn the_outputs_a_generated_stack_would_produce_round_trip_into_a_profile() {
    // Ties the two halves of this file together: the output names scraped from the
    // generated stack are exactly the ones `StackOutputs` reads, so a rename on
    // either side fails here rather than after a deploy.
    let stack = source(&project_for(PlanRequest::default()), STACK_PATH);
    let declared = declared_outputs(&stack);

    let mut fields = serde_json::Map::new();
    for name in &declared {
        let value = match name.as_str() {
            "TrustAnchorArn" => TRUST_ANCHOR.to_string(),
            "RolesAnywhereProfileArn" => RA_PROFILE.to_string(),
            "RoleArn" => ROLE.to_string(),
            "Region" => "us-east-1".to_string(),
            "KeystoneKeyId" => KEY_ID.to_string(),
            "DeviceSanUri" => DEVICE_SAN.to_string(),
            other => panic!("unaccounted output {other}"),
        };
        fields.insert(name.clone(), serde_json::Value::String(value));
    }

    let json = serde_json::json!({ "KeystonePersonal": fields }).to_string();
    let outputs = StackOutputs::parse(&json, None).expect("the stack's own outputs parse");
    assert_eq!(outputs.resolved_region(), Some("us-east-1"));
    assert_eq!(outputs.key_id.as_deref(), Some(KEY_ID));

    let scratch = TempDir::new("sync-roundtrip");
    let store = store_with_fresh_profile(&scratch);
    let report = sync_profile(&store, "personal", &outputs, false).expect("sync succeeds");
    assert!(report.saved);
    store
        .load_config()
        .unwrap()
        .profile("personal")
        .unwrap()
        .require_ready("personal")
        .expect("the profile is usable");
}

// -- The real synth ---------------------------------------------------------

fn npm_available() -> bool {
    std::process::Command::new("npm")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run(command: &str, args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    let output = std::process::Command::new(command)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {command}: {error}"));
    println!(
        "$ {command} {}\n{}{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// `npm install`, `cdk synth`, then assertions against the template.
///
/// One test rather than several so the install cost is paid once.
#[test]
#[ignore = "runs npm install and cdk synth; needs a network and a few minutes"]
fn the_generated_project_synthesizes_and_the_template_is_correct() {
    assert!(npm_available(), "npm is required for this test");

    let scratch = TempDir::new("cdk-synth");
    let root = scratch.join("project");
    project_for(PlanRequest::default())
        .write(&root, false)
        .expect("the project writes");

    assert!(
        run("npm", &["install", "--no-audit", "--no-fund"], &root)
            .status
            .success(),
        "npm install failed"
    );

    // Through the locally installed CDK, so no global install is needed and the
    // version is the one package.json pins.
    assert!(
        run("npx", &["--no-install", "cdk", "synth", "--quiet"], &root)
            .status
            .success(),
        "cdk synth failed"
    );

    let template_path = root.join("cdk.out/KeystonePersonal.template.json");
    let template: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&template_path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", template_path.display())),
    )
    .expect("the template is JSON");

    let resources = template["Resources"]
        .as_object()
        .expect("the template has resources");
    let types: Vec<&str> = resources
        .values()
        .filter_map(|resource| resource["Type"].as_str())
        .collect();

    // Expected resources exist, exactly once each.
    for expected in [
        "AWS::RolesAnywhere::TrustAnchor",
        "AWS::RolesAnywhere::Profile",
        "AWS::IAM::Role",
    ] {
        assert_eq!(
            types.iter().filter(|found| **found == expected).count(),
            1,
            "expected exactly one {expected}, found {types:?}"
        );
    }

    let rendered = template.to_string();

    // The external CA bundle is embedded correctly: the resolved template must
    // carry the certificate itself, not a path that will not exist at deploy time.
    let ca_body_line = fixture("ca.pem")
        .lines()
        .nth(1)
        .expect("the CA PEM has a body line")
        .to_string();
    assert!(
        rendered.contains(&ca_body_line),
        "the synthesized trust anchor does not embed the CA certificate"
    );
    assert!(
        !rendered.contains("keystone-ca.pem"),
        "a file path leaked into the template"
    );
    assert!(
        !rendered.contains("PRIVATE KEY"),
        "the template holds key material"
    );

    // No administrator or wildcard permissions survive synthesis.
    for forbidden in [
        "AdministratorAccess",
        "PowerUserAccess",
        r#""Action":"*""#,
        r#""Action":["*"]"#,
    ] {
        assert!(
            !rendered.contains(forbidden),
            "the template contains {forbidden}"
        );
    }

    // The SAN restriction survives synthesis, which a source-level check cannot
    // confirm: a condition attached to the wrong policy object would vanish here.
    assert!(
        rendered.contains("aws:PrincipalTag/x509SAN/URI"),
        "{rendered}"
    );
    assert!(
        rendered.contains(DEVICE_SAN),
        "the device SAN is not in the template"
    );
    let role = resources
        .values()
        .find(|resource| resource["Type"] == "AWS::IAM::Role")
        .expect("a role");
    let trust_policy = role["Properties"]["AssumeRolePolicyDocument"].to_string();
    assert!(
        trust_policy.contains("aws:PrincipalTag/x509SAN/URI"),
        "the restriction is not in the trust policy: {trust_policy}"
    );
    assert!(trust_policy.contains("\"Deny\""), "{trust_policy}");
    assert!(trust_policy.contains("aws:SourceArn"), "{trust_policy}");

    // The role cannot issue a session longer than the profile grants.
    let plan = plan_with(PlanRequest::default());
    assert_eq!(
        role["Properties"]["MaxSessionDuration"],
        serde_json::json!(plan.duration_seconds)
    );

    // Outputs have the expected names.
    let outputs = template["Outputs"]
        .as_object()
        .expect("the template has outputs");
    for name in declared_outputs(&source(&project_for(PlanRequest::default()), STACK_PATH)) {
        assert!(
            outputs.contains_key(&name),
            "the source declares {name} but the template does not: {:?}",
            outputs.keys().collect::<Vec<_>>()
        );
    }
}

/// The generated Jest suite must pass, since it ships to the user and is what
/// they will run after editing the stack.
#[test]
#[ignore = "runs npm install and npm test; needs a network and a few minutes"]
fn the_generated_test_suite_passes() {
    assert!(npm_available(), "npm is required for this test");

    let scratch = TempDir::new("cdk-jest");
    let root = scratch.join("project");
    project_for(PlanRequest::default())
        .write(&root, false)
        .expect("the project writes");

    assert!(
        run("npm", &["install", "--no-audit", "--no-fund"], &root)
            .status
            .success(),
        "npm install failed"
    );
    assert!(
        run("npm", &["test"], &root).status.success(),
        "the generated test suite failed"
    );
}

/// Every generation mode must compile, which catches template errors that a text
/// match cannot — an unbalanced brace inside a conditional block, for instance.
#[test]
#[ignore = "runs npm install and tsc for each mode; needs a network and several minutes"]
fn the_generated_typescript_compiles_in_every_mode() {
    assert!(npm_available(), "npm is required for this test");

    let variants: Vec<(&str, PlanRequest)> = vec![
        ("default", PlanRequest::default()),
        (
            "inline-policy",
            PlanRequest {
                permissions: Some(
                    PermissionMode::inline(
                        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}"#,
                    )
                    .unwrap(),
                ),
                ..Default::default()
            },
        ),
        (
            "managed-policies",
            PlanRequest {
                permissions: Some(
                    PermissionMode::managed(vec![
                        "arn:aws:iam::aws:policy/ReadOnlyAccess".to_string(),
                        "arn:aws:iam::aws:policy/AWSCloudTrail_ReadOnlyAccess".to_string(),
                    ])
                    .unwrap(),
                ),
                ..Default::default()
            },
        ),
        (
            "existing-role",
            PlanRequest {
                existing_role_arn: Some(
                    "arn:aws:iam::123456789012:role/ManagedElsewhere".to_string(),
                ),
                ..Default::default()
            },
        ),
        (
            "existing-trust-anchor",
            PlanRequest {
                existing_trust_anchor_arn: Some(
                    "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/tttt".to_string(),
                ),
                ..Default::default()
            },
        ),
    ];

    let scratch = TempDir::new("cdk-tsc");
    for (label, request) in variants {
        let root = scratch.join(label);
        project_for(request)
            .write(&root, false)
            .expect("the project writes");
        assert!(
            run("npm", &["install", "--no-audit", "--no-fund"], &root)
                .status
                .success(),
            "npm install failed for {label}"
        );
        assert!(
            run("npx", &["--no-install", "tsc", "--noEmit"], &root)
                .status
                .success(),
            "tsc rejected the {label} variant"
        );
        // And the mode's own generated tests pass, which is where the
        // resource-count assertions for that mode live.
        assert!(
            run("npm", &["test"], &root).status.success(),
            "the generated test suite failed for {label}"
        );
    }
}
