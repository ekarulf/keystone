//! Secure Enclave integration tests on real Apple silicon.
//!
//! The design's ten steps:
//!
//! Generate an unattended key (1), sign without a UI prompt (2), restart the
//! process (3), restore and sign again (4), lock the Mac (5), test expected
//! accessibility behavior (6), reboot before first unlock (7), confirm signing
//! fails (8), log in (9), confirm signing succeeds (10).
//!
//! Steps 1 through 4 are automated here. Step 3 in particular is a real process
//! restart: the identity is persisted through [`keystone_core::store::Store`],
//! and a second test binary process — this same binary, re-executed with an
//! environment variable — restores from that file and signs. A test that merely
//! dropped the `SecureEnclaveIdentity` and rebuilt it in-process would pass even
//! if CryptoKit were caching the key in memory, which is exactly the failure this
//! step exists to catch.
//!
//! Steps 5 through 10 cannot be automated from inside a test process: they need
//! the screen locked, and then the machine rebooted and left at the login window.
//! `keystone_manual_checklist` prints the procedure and the expected outcome for
//! each, so the sequence is recorded and runnable rather than described only in
//! the design document. Run it with:
//!
//! ```text
//! cargo test -p keystone-tests --test integration_secure_enclave -- --ignored --nocapture
//! ```
//!
//! Every automated test returns early when no enclave is present, so the suite
//! passes in a VM. A missing enclave in production is a hard error — Keystone
//! never falls back to a software key.

#![cfg(target_os = "macos")]

use keystone_core::config::{KeyAccessibility, Paths};
use keystone_core::error::KeystoneError;
use keystone_core::identity::KeyId;
use keystone_core::signer::KeystoneSigningIdentity as _;
use keystone_core::store::Store;
use keystone_macos::{enclave, AccessPolicy, SecureEnclaveIdentity};
use keystone_tests::TempDir;
use time::OffsetDateTime;

const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

/// The environment variable that turns this binary into the child half of the
/// restart test, set to the store root the parent wrote the identity into.
const RESTART_CHILD_ROOT: &str = "KEYSTONE_TEST_RESTART_ROOT";
/// The key ID the child should restore.
const RESTART_CHILD_KEY_ID: &str = "KEYSTONE_TEST_RESTART_KEY_ID";
/// The message the child signs, so the parent can verify the result.
const RESTART_MESSAGE: &[u8] = b"keystone restart-and-sign integration check";

fn enclave_present() -> bool {
    enclave::is_available().expect("querying the Secure Enclave must not fail on macOS")
}

fn store_at(root: &std::path::Path) -> Store {
    Store::new(Paths::rooted_at(root))
}

// -- Step 1: generate an unattended key -------------------------------------

#[test]
fn step_1_a_generated_key_is_unattended() {
    if !enclave_present() {
        return;
    }
    let generated =
        SecureEnclaveIdentity::generate(KeyId::generate(), AccessPolicy::default(), NOW)
            .expect("generating a Secure Enclave key");

    // "Keystone must not silently add biometric or user-presence requirements."
    assert!(
        !AccessPolicy::default().requires_user_interaction(),
        "the default policy must not require Touch ID"
    );
    assert_eq!(
        generated.identity.accessibility(),
        KeyAccessibility::AfterFirstUnlock
    );
    assert_eq!(
        generated.metadata.key_type,
        keystone_core::identity::KeyType::SecureEnclaveP256Signing
    );
}

// -- Step 2: sign without a UI prompt ---------------------------------------

#[test]
fn step_2_signing_needs_no_prompt_and_verifies_against_the_public_key() {
    if !enclave_present() {
        return;
    }
    let generated =
        SecureEnclaveIdentity::generate(KeyId::generate(), AccessPolicy::default(), NOW)
            .expect("generating a Secure Enclave key");

    // If this raised a prompt the test would block rather than fail, so the
    // timing is the assertion: a prompt cannot be dismissed in a test harness.
    let signature = generated
        .identity
        .sign_message_ecdsa_sha256(RESTART_MESSAGE)
        .expect("signing must not require user interaction");

    keystone_pki::verify_der_signature(
        &generated.identity.public_key_sec1().unwrap(),
        RESTART_MESSAGE,
        signature.as_bytes(),
    )
    .expect("the signature verifies as ECDSA-SHA256 over the message");
}

// -- Steps 3 and 4: restart the process, restore, and sign again ------------

#[test]
fn steps_3_and_4_a_new_process_restores_the_key_and_signs_with_it() {
    if !enclave_present() {
        return;
    }
    // The child branch: this binary re-executed by the parent below.
    if std::env::var_os(RESTART_CHILD_ROOT).is_some() {
        return;
    }

    let scratch = TempDir::new("restart");
    let store = store_at(scratch.path());

    let generated =
        SecureEnclaveIdentity::generate(KeyId::generate(), AccessPolicy::default(), NOW)
            .expect("generating a Secure Enclave key");
    let key_id = generated.identity.key_id().clone();
    let expected_public_key = generated.identity.public_key_sec1().unwrap();
    store
        .save_identity(&generated.metadata)
        .expect("the identity persists");

    // Drop everything the parent holds. The child gets only the file.
    drop(generated);
    drop(store);

    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        // Run only the child helper, and let its output through.
        .args(["restart_child_restores_and_signs", "--exact", "--nocapture"])
        .env(RESTART_CHILD_ROOT, scratch.path())
        .env(RESTART_CHILD_KEY_ID, key_id.as_str())
        .output()
        .expect("re-executing the test binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the child process failed to restore and sign:\n{stdout}\n{stderr}"
    );

    // The child prints the public key it restored and the signature it produced.
    let public_key_hex = extract(&stdout, "restored-public-key: ");
    let signature_hex = extract(&stdout, "signature: ");
    assert_eq!(
        public_key_hex,
        hex::encode(expected_public_key),
        "a new process must restore the same key, not a new one"
    );

    keystone_pki::verify_der_signature(
        &expected_public_key,
        RESTART_MESSAGE,
        &hex::decode(signature_hex).expect("the child printed hex"),
    )
    .expect("the signature made in the child process verifies against the original key");

    // Nothing secret should have crossed the process boundary.
    assert!(
        !stdout.contains("PRIVATE") && !stderr.contains("PRIVATE"),
        "the child must not print key material"
    );
}

/// The child half of the restart test. Not a check on its own.
///
/// Named without a `step_` prefix so it reads as machinery, and gated on the
/// environment variable so a plain `cargo test` run skips it.
#[test]
fn restart_child_restores_and_signs() {
    let Some(root) = std::env::var_os(RESTART_CHILD_ROOT) else {
        return;
    };
    let key_id = std::env::var(RESTART_CHILD_KEY_ID).expect("the parent sets the key id");
    let key_id = KeyId::parse(key_id).expect("the parent passes a valid key id");

    let store = store_at(std::path::Path::new(&root));
    let metadata = store
        .load_identity(&key_id)
        .expect("the identity file written by the parent process is readable");
    let identity = SecureEnclaveIdentity::restore(&metadata, AccessPolicy::default())
        .expect("a Secure Enclave key survives a process restart");

    let signature = identity
        .sign_message_ecdsa_sha256(RESTART_MESSAGE)
        .expect("the restored key signs");

    println!(
        "restored-public-key: {}",
        hex::encode(identity.public_key_sec1().unwrap())
    );
    println!("signature: {}", hex::encode(signature.as_bytes()));
}

fn extract(haystack: &str, prefix: &str) -> String {
    haystack
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .unwrap_or_else(|| panic!("the child did not print {prefix:?}:\n{haystack}"))
        .trim()
        .to_string()
}

// -- Step 6, in the part that can be automated ------------------------------

#[test]
fn step_6_both_accessibilities_produce_a_usable_key() {
    if !enclave_present() {
        return;
    }
    for accessibility in [
        KeyAccessibility::AfterFirstUnlock,
        KeyAccessibility::WhenUnlocked,
    ] {
        let policy = AccessPolicy::new(accessibility);
        let generated = match SecureEnclaveIdentity::generate(KeyId::generate(), policy, NOW) {
            Ok(generated) => generated,
            // -25308 is `errSecInteractionNotAllowed`: a `WhenUnlocked` key
            // cannot be *created* while the screen is locked. That is the
            // accessibility working as specified, and it is what step 6 is about,
            // so it is not a failure here.
            Err(error) if format!("{error}").contains("-25308") => {
                println!("skipping {accessibility:?}: the screen is locked (errSecInteractionNotAllowed)");
                continue;
            }
            Err(error) => panic!("generating a {accessibility:?} key: {error}"),
        };
        assert_eq!(generated.identity.accessibility(), accessibility);
        generated.identity.self_test().expect("the new key signs");
    }
}

#[test]
fn a_signing_failure_is_never_downgraded_to_a_software_key() {
    // "If Secure Enclave signing fails, Keystone fails closed." The only way to
    // provoke a failure without hardware cooperation is to corrupt the key
    // reference; what matters is that the result is an error and not a signature.
    if !enclave_present() {
        return;
    }
    let generated =
        SecureEnclaveIdentity::generate(KeyId::generate(), AccessPolicy::default(), NOW)
            .expect("generating a Secure Enclave key");

    let mut corrupt = generated.metadata.clone();
    corrupt.opaque_key_reference = "AAAA".to_string();
    let error = SecureEnclaveIdentity::restore(&corrupt, AccessPolicy::default())
        .expect_err("a corrupt key reference must not yield a usable identity");
    assert!(matches!(error, KeystoneError::KeyUnavailable), "{error}");
}

// -- Steps 5 and 7 through 10: the manual procedure -------------------------

/// Print the manual checklist for the steps a test process cannot perform.
///
/// `#[ignore]` because it asserts nothing: it exists so the procedure lives in
/// the test suite next to the automated steps, with the expected outcome for
/// each, rather than only in prose.
#[test]
#[ignore = "prints the manual procedure for design steps 5 and 7 through 10"]
fn keystone_manual_checklist() {
    let report = enclave::report();
    println!("Secure Enclave: {report:?}\n");
    println!(
        "\
Steps 1 to 4 and 6 are automated in this file. The following need physical
access to the machine. Run each `keystone` command from a checkout with a real
profile enrolled (see docs/DESIGN.md, \"Bootstrap\").

Step 5 — lock the Mac.
  1. Enroll a profile whose key uses the default accessibility
     (after-first-unlock), and confirm `keystone test --profile <name>` succeeds.
  2. Lock the screen (Control-Command-Q). Do not log out.
  3. From another session, or over SSH, run:
         keystone credential-process --profile <name>
  Expected: the exchange succeeds. An after-first-unlock key stays usable while
  the screen is locked, which is why it is the default — `credential_process`
  runs with no user attached.

Step 6 — accessibility behavior, the locked half.
  4. Repeat step 5 for a profile enrolled with when-unlocked accessibility.
  Expected: signing fails while the screen is locked, with a Keychain
  interaction error, and succeeds again after unlocking. Keystone must report the
  failure and exit nonzero; it must not fall back to any other key.

Steps 7 and 8 — reboot before first unlock.
  5. Reboot the Mac. At the login window, before typing a password, run over SSH:
         keystone credential-process --profile <name>
  Expected: signing fails. Nothing is written to standard output — check with
         keystone credential-process --profile <name> > /tmp/out; wc -c /tmp/out
  which must report 0 bytes, and the exit status must be nonzero.

Steps 9 and 10 — log in and retry.
  6. Log in at the console.
  7. Run the same command again.
  Expected: signing succeeds and credential JSON appears on standard output.

Record the outcome of each step in the pull request that changes signing or
accessibility behavior."
    );
}
