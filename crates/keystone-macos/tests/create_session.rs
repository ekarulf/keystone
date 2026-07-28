//! The Phase 1 deliverable: `Secure Enclave key → CreateSession`.
//!
//! Phase 0 proved the AWS protocol with a software P-256 key. This is the same
//! exchange — the same signing code, the same stub server, the same response
//! parsing — with the signer replaced by a key that was generated inside the
//! Secure Enclave and cannot be exported. What it proves that the unit tests
//! cannot is that the two halves fit: CryptoKit's raw `r || s` signature over
//! the string-to-sign, once converted to DER and hex-encoded, is a signature
//! AWS can verify against the certificate presented in `x-amz-x509`.
//!
//! Every test returns early on a machine with no Secure Enclave rather than
//! failing, so the suite still runs on CI without Apple silicon. A missing
//! enclave in *production* is a hard error — see `enclave::require_available`.
//!
//! The design's "confirm unattended behavior" is checked here too: these tests
//! generate keys, restore them, and sign with them, and the run must not raise a
//! Touch ID prompt. A prompt would block `credential_process`, which has no
//! terminal and no user attached.

#![cfg(target_os = "macos")]

use std::time::Duration;

use keystone_core::identity::KeyId;
use keystone_core::signer::KeystoneSigningIdentity as _;
use keystone_core::time::FixedClock;
use keystone_macos::{AccessPolicy, CertificateIdentity, SecureEnclaveIdentity};
use keystone_pki::params::{DeviceCertificateSpec, EphemeralCaSpec};
use keystone_pki::ParsedCertificate;
use keystone_roles_anywhere::testing::stub_server::{StubResponse, StubServer};
use keystone_roles_anywhere::{
    AwsX509Identity, CreateSessionRequest, RolesAnywhereClient, TransportConfig,
};
use time::OffsetDateTime;

const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);
const REGION: &str = "us-east-1";
const DEVICE_NAME: &str = "erik-macbook";

const SUCCESS_BODY: &str = r#"{
  "credentialSet": [
    {
      "assumedRoleUser": {
        "arn": "arn:aws:sts::123456789012:assumed-role/KeystonePersonalMac/erik-macbook"
      },
      "credentials": {
        "accessKeyId": "ASIAEXAMPLE",
        "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "sessionToken": "IQoJb3JpZ2luX2VjEXAMPLETOKEN",
        "expiration": "2026-07-26T02:15:00Z"
      }
    }
  ]
}"#;

fn request() -> CreateSessionRequest {
    CreateSessionRequest {
        profile_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:profile/p".to_string(),
        role_arn: "arn:aws:iam::123456789012:role/KeystonePersonalMac".to_string(),
        trust_anchor_arn: "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/t".to_string(),
        duration_seconds: 3600,
        role_session_name: Some(DEVICE_NAME.to_string()),
    }
}

/// What a completed `keystone bootstrap` leaves behind.
struct Bootstrap {
    identity: CertificateIdentity,
    /// The ephemeral CA, which is what a trust anchor would hold.
    anchor: ParsedCertificate,
    /// The metadata a real run would persist, for the restore test.
    metadata: keystone_core::identity::IdentityMetadata,
}

/// Generate an enclave key and issue it a certificate from an ephemeral CA.
///
/// Returns `None` when this machine has no Secure Enclave.
fn bootstrap() -> Option<Bootstrap> {
    if !keystone_macos::is_available().expect("querying the Secure Enclave") {
        return None;
    }

    let key_id = KeyId::generate();
    let generated = SecureEnclaveIdentity::generate(key_id.clone(), AccessPolicy::default(), NOW)
        .expect("generating a Secure Enclave key");
    let public_key = generated
        .identity
        .public_key_sec1()
        .expect("exporting the public key");

    let device = DeviceCertificateSpec::new(DEVICE_NAME, key_id.clone(), NOW);
    let ca = EphemeralCaSpec::new(key_id, NOW);
    let output = keystone_pki::ephemeral_ca::issue(&public_key, &device, &ca, NOW)
        .expect("issuing a device certificate");

    let anchor = output.ca_certificate.clone();
    let chain = output.chain_der();
    let identity =
        CertificateIdentity::new(generated.identity, output.device_certificate, chain, NOW)
            .expect("pairing the key with its certificate");

    Some(Bootstrap {
        identity,
        anchor,
        metadata: generated.metadata,
    })
}

fn client<I: AwsX509Identity>(
    identity: I,
    server: &StubServer,
) -> RolesAnywhereClient<I, FixedClock> {
    RolesAnywhereClient::new(
        identity,
        REGION,
        FixedClock(NOW),
        TransportConfig {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
        },
    )
    .expect("client builds")
    .with_endpoint_override(server.base_url())
    .with_sleeper(|_| {})
}

#[test]
fn a_secure_enclave_key_is_exchanged_for_temporary_credentials() {
    // The Phase 1 deliverable. Nothing here is a mock except the AWS endpoint:
    // the private key is in hardware, the certificate is real X.509, and the
    // request is the one AWS would receive.
    let Some(boot) = bootstrap() else { return };

    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&boot.identity, &server)
        .create_session(&request())
        .expect("credentials issued");

    assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");
    assert_eq!(
        result.credentials.expiration,
        time::macros::datetime!(2026-07-26 02:15:00 UTC)
    );
    assert!(result.credentials.validate(NOW).is_ok());
    assert_eq!(server.request_count(), 1);
}

#[test]
fn the_enclave_signature_on_the_wire_verifies_against_the_device_certificate() {
    // The check that the two halves fit. AWS recomputes the string-to-sign from
    // the request it received and verifies the `Signature=` hex against the
    // public key in the certificate from `x-amz-x509`. This does the same thing,
    // so a raw-versus-DER or double-hash mistake fails here rather than as an
    // opaque AWS rejection.
    let Some(boot) = bootstrap() else { return };

    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    client(&boot.identity, &server)
        .create_session(&request())
        .expect("credentials issued");

    let sent = server.requests().remove(0);
    let signature_hex = sent
        .header("authorization")
        .and_then(|value| value.split("Signature=").nth(1))
        .expect("signature present");
    let signature = hex::decode(signature_hex).expect("hex signature");

    let mut headers = keystone_roles_anywhere::signing::SignedHeaders::new();
    for name in ["content-type", "host", "x-amz-date", "x-amz-x509"] {
        headers.insert(name, sent.header(name).expect(name));
    }
    let canonical = keystone_roles_anywhere::signing::canonical_request(&headers, &sent.body);
    let string_to_sign = keystone_roles_anywhere::signing::string_to_sign(
        keystone_roles_anywhere::signing::ALGORITHM_ECDSA_SHA256,
        NOW,
        REGION,
        &canonical,
    )
    .expect("string to sign");

    // Verified against the certificate, not against the identity object: this is
    // the path AWS takes, and it would catch a certificate that names a
    // different key than the one that signed.
    keystone_pki::ephemeral_ca::verify_device_signature(
        boot.identity.certificate(),
        string_to_sign.as_bytes(),
        &keystone_core::signer::DerEcdsaSignature::from_der(signature),
    )
    .expect("the enclave signature does not verify against the device certificate");

    // And the certificate the request presents chains to the trust anchor AWS
    // would hold.
    keystone_pki::validate_chain(boot.identity.certificate(), &[], &boot.anchor, NOW)
        .expect("device certificate does not chain to the trust anchor");
}

#[test]
fn the_certificate_header_carries_the_leaf_and_the_credential_field_the_serial() {
    // Roles Anywhere departs from SigV4 twice here: the certificate travels in
    // `x-amz-x509` as base64 DER, and the `Credential=` field starts with the
    // serial in *decimal*, not the access key id.
    let Some(boot) = bootstrap() else { return };

    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    client(&boot.identity, &server)
        .create_session(&request())
        .expect("credentials issued");

    let sent = server.requests().remove(0);

    let encoded = sent.header("x-amz-x509").expect("x-amz-x509 header");
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .expect("header is base64");
    assert_eq!(
        decoded,
        boot.identity.certificate().der(),
        "the header does not carry the leaf certificate"
    );
    // An ephemeral-CA bootstrap presents no intermediates, so there is no
    // `x-amz-x509-chain`.
    assert_eq!(sent.header("x-amz-x509-chain"), None);

    let serial = boot.identity.certificate().serial_decimal.clone();
    assert!(
        serial.chars().all(|c| c.is_ascii_digit()),
        "serial {serial} is not decimal"
    );
    let authorization = sent.header("authorization").expect("authorization header");
    assert!(
        authorization.contains(&format!(
            "Credential={serial}/20260726/us-east-1/rolesanywhere/aws4_request"
        )),
        "{authorization}"
    );
    assert!(
        authorization.starts_with("AWS4-X509-ECDSA-SHA256 "),
        "{authorization}"
    );
}

#[test]
fn a_restored_identity_signs_a_later_session_without_regenerating_the_key() {
    // The refresh path. `credential-process` runs as a fresh process on every
    // expiry, so it restores the key from the identity file rather than
    // generating one — and must reach the same key, unattended.
    let Some(boot) = bootstrap() else { return };

    let restored = SecureEnclaveIdentity::restore(&boot.metadata, AccessPolicy::default())
        .expect("restoring the Secure Enclave key");
    assert_eq!(
        restored.public_key_fingerprint(),
        boot.identity.identity().public_key_fingerprint(),
        "restore reached a different key"
    );

    let identity = CertificateIdentity::new(
        restored,
        boot.identity.certificate().clone(),
        Vec::new(),
        NOW,
    )
    .expect("the restored key still matches its certificate");

    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&identity, &server)
        .create_session(&request())
        .expect("credentials issued");
    assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");
}

#[test]
fn a_retry_is_signed_again_by_the_enclave() {
    // Two attempts means two enclave signatures. ECDSA nonces are random, so
    // even at the same timestamp over identical bytes the signatures differ —
    // which also confirms the second attempt was signed rather than replayed.
    let Some(boot) = bootstrap() else { return };

    let server = StubServer::start(vec![
        StubResponse::error(503, r#"{"message":"unavailable"}"#),
        StubResponse::ok(SUCCESS_BODY),
    ]);
    let result = client(&boot.identity, &server)
        .create_session(&request())
        .expect("second attempt succeeds");
    assert_eq!(result.credentials.access_key_id, "ASIAEXAMPLE");

    let captured = server.requests();
    assert_eq!(captured.len(), 2);
    assert_ne!(
        captured[0].header("authorization"),
        captured[1].header("authorization"),
        "the retry reused the first attempt's signature"
    );
    // Same clock, so the only difference is the signature itself.
    assert_eq!(
        captured[0].header("x-amz-date"),
        captured[1].header("x-amz-date")
    );
}

#[test]
fn nothing_secret_appears_in_a_debug_rendering_of_the_exchange() {
    // The design forbids logging session tokens, secret access keys,
    // authorization headers, and opaque Secure Enclave key references. These are
    // the three objects a diagnostic would be tempted to print.
    let Some(boot) = bootstrap() else { return };

    let server = StubServer::start(vec![StubResponse::ok(SUCCESS_BODY)]);
    let result = client(&boot.identity, &server)
        .create_session(&request())
        .expect("credentials issued");

    let rendered = format!(
        "{result:?} {:?} {:?}",
        boot.identity,
        boot.identity.identity()
    );
    assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
    assert!(!rendered.contains("IQoJb3JpZ2luX2Vj"), "{rendered}");
    assert!(
        !rendered.contains(&boot.metadata.opaque_key_reference),
        "the opaque key reference leaked into a debug rendering"
    );
}
