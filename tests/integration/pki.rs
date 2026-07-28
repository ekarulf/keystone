//! PKI tests against certificates built by OpenSSL.
//!
//! The design's PKI test list, checked against fixtures produced by
//! `tests/fixtures/generate.sh` rather than by `keystone-pki` itself:
//!
//! * generated CA validates as a CA;
//! * leaf validates against generated CA;
//! * leaf cannot sign certificates;
//! * leaf key matches the Secure Enclave key;
//! * incorrect key is rejected;
//! * incorrect SAN is rejected;
//! * expired certificate is rejected;
//! * malformed chain is rejected;
//! * no CA private key appears in the output tree.
//!
//! `keystone-pki`'s own unit tests cover the same rules against certificates it
//! generated. Those catch logic errors; these catch a shared assumption between
//! Keystone's issuer and Keystone's validator — the case where both sides agree
//! on an encoding that no other X.509 implementation produces.

use keystone_core::error::KeystoneError;
use keystone_pki::validate::{
    validate_ca_certificate, validate_chain, validate_device_certificate, ValidationContext,
};
use keystone_pki::ParsedCertificate;
use keystone_tests::{fixture, fixture_key_id, fixtures_dir, FIXTURE_SAN};
use time::OffsetDateTime;

/// Inside every fixture window that is meant to be valid, and after the expired
/// fixture's `notAfter`.
const NOW: OffsetDateTime = time::macros::datetime!(2026-07-26 01:15:00 UTC);

fn certificate(name: &str) -> ParsedCertificate {
    ParsedCertificate::from_pem(&fixture(name))
        .unwrap_or_else(|error| panic!("fixture {name} should parse: {error}"))
}

/// The public key of the fixture device key, as the enclave would report it.
///
/// Derived from the private key rather than read from the certificate, so the
/// public-key comparison is a real comparison.
fn fixture_device_public_key() -> [u8; 65] {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::DecodePrivateKey as _;

    let key =
        SigningKey::from_pkcs8_pem(&fixture("device-key.pem")).expect("the fixture key loads");
    let encoded = key.verifying_key().to_encoded_point(false);
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(encoded.as_bytes());
    bytes
}

fn expecting_the_fixture_device() -> ValidationContext {
    ValidationContext::new(NOW)
        .expecting_key(fixture_device_public_key())
        .expecting_key_id(fixture_key_id())
}

#[test]
fn the_openssl_ca_validates_as_a_ca() {
    let ca = certificate("ca.pem");
    validate_ca_certificate(&ca, NOW).expect("an OpenSSL CA satisfies Keystone's CA rules");
    assert!(ca.is_ca);
    assert!(ca.basic_constraints_critical);
    assert_eq!(ca.path_len, Some(0), "the ephemeral CA issues one leaf");
    assert!(ca.key_usage_key_cert_sign);
    assert!(!ca.key_usage_digital_signature);
}

#[test]
fn the_openssl_leaf_validates_as_a_device_certificate() {
    let leaf = certificate("device.pem");
    validate_device_certificate(&leaf, &expecting_the_fixture_device())
        .expect("an OpenSSL leaf satisfies Keystone's device rules");
    assert_eq!(leaf.version, 3);
    assert!(leaf.key_usage_digital_signature);
    assert!(!leaf.is_ca);
    assert_eq!(leaf.uri_sans, vec![FIXTURE_SAN.to_string()]);
}

#[test]
fn the_openssl_leaf_chains_to_the_openssl_ca() {
    let leaf = certificate("device.pem");
    let ca = certificate("ca.pem");
    validate_chain(&leaf, &[], &ca, NOW).expect("the fixture chain verifies");
}

#[test]
fn the_leaf_cannot_sign_certificates() {
    // A leaf that could act as a CA would let one compromised device mint
    // identities for others under the same trust anchor.
    let leaf = certificate("device.pem");
    assert!(!leaf.is_ca);
    assert!(!leaf.key_usage_key_cert_sign);
    assert!(!leaf.key_usage_crl_sign);
    assert!(
        leaf.basic_constraints_critical,
        "CA:FALSE is asserted, not merely absent"
    );

    // And Keystone refuses to treat it as one.
    let error = validate_ca_certificate(&leaf, NOW).unwrap_err();
    assert!(
        matches!(error, KeystoneError::InvalidCertificateChain(_)),
        "{error}"
    );
}

#[test]
fn the_leaf_public_key_matches_the_device_key() {
    let leaf = certificate("device.pem");
    assert_eq!(leaf.public_key_sec1, fixture_device_public_key());
    // Uncompressed SEC1, which is the only form the Secure Enclave exports.
    assert_eq!(leaf.public_key_sec1[0], 0x04);
}

#[test]
fn a_certificate_for_another_key_is_rejected() {
    // Signed by the same trusted CA, with the correct SAN and validity window.
    // Only the public-key comparison distinguishes it, which is why that check
    // exists: without it Keystone would present an identity it cannot sign for.
    let other = certificate("device-other-key.pem");
    validate_chain(&other, &[], &certificate("ca.pem"), NOW)
        .expect("it really is issued by the trusted CA");

    let error = validate_device_certificate(&other, &expecting_the_fixture_device()).unwrap_err();
    assert!(
        matches!(error, KeystoneError::CertificateKeyMismatch),
        "{error}"
    );
}

#[test]
fn a_certificate_without_the_device_san_is_rejected() {
    let no_san = certificate("device-no-san.pem");
    assert!(no_san.uri_sans.is_empty());
    let error = validate_device_certificate(&no_san, &expecting_the_fixture_device()).unwrap_err();
    assert!(matches!(error, KeystoneError::MissingDeviceSan), "{error}");
}

#[test]
fn a_certificate_naming_another_device_is_rejected() {
    // The SAN is well formed but names a different key ID. The error should say
    // so rather than reporting a missing SAN.
    let leaf = certificate("device.pem");
    let context = ValidationContext::new(NOW)
        .expecting_key(fixture_device_public_key())
        .expecting_key_id(keystone_core::identity::KeyId::parse("someotherdevice").unwrap());
    let error = validate_device_certificate(&leaf, &context)
        .unwrap_err()
        .to_string();
    assert!(error.contains("someotherdevice"), "{error}");
}

#[test]
fn an_expired_certificate_is_rejected() {
    let expired = certificate("device-expired.pem");
    assert!(expired.not_after < NOW);
    let error = validate_device_certificate(&expired, &expecting_the_fixture_device()).unwrap_err();
    match error {
        KeystoneError::CertificateExpired(when) => assert_eq!(when, expired.not_after),
        other => panic!("expected an expiry error, got {other}"),
    }
}

#[test]
fn a_certificate_not_yet_valid_is_rejected() {
    let leaf = certificate("device.pem");
    let before = leaf.not_before - time::Duration::days(1);
    let context = ValidationContext::new(before)
        .expecting_key(fixture_device_public_key())
        .expecting_key_id(fixture_key_id());
    assert!(matches!(
        validate_device_certificate(&leaf, &context),
        Err(KeystoneError::CertificateNotYetValid)
    ));
}

#[test]
fn a_leaf_from_another_ca_does_not_chain_to_this_trust_anchor() {
    // The same device key, correctly named, under a CA that is not the anchor.
    // Only the signature check catches this: the subject names differ, but a
    // validator that compared names alone would still be fooled by a CA with a
    // matching subject, which is the next test.
    let other = certificate("device-other-ca.pem");
    validate_device_certificate(&other, &expecting_the_fixture_device())
        .expect("the leaf itself is well formed");

    let error = validate_chain(&other, &[], &certificate("ca.pem"), NOW).unwrap_err();
    assert!(
        matches!(error, KeystoneError::InvalidCertificateChain(_)),
        "{error}"
    );
}

#[test]
fn a_chain_is_verified_by_signature_and_not_by_issuer_name() {
    // OpenSSL agrees: this is the cross-check that the fixture set itself is
    // sound, and it is the reason `x509-parser` is built with "verify".
    let leaf = certificate("device.pem");
    let other_ca = certificate("other-ca.pem");
    assert_ne!(leaf.issuer, other_ca.subject);
    assert!(validate_chain(&leaf, &[], &other_ca, NOW).is_err());
}

#[test]
fn a_malformed_certificate_is_refused_at_parse_time() {
    // Truncation, trailing bytes, and text that is not DER at all. Each must
    // produce an error rather than a partially populated certificate.
    let leaf = certificate("device.pem");
    let der = leaf.der();

    let truncated = ParsedCertificate::from_der(&der[..der.len() / 2]).unwrap_err();
    assert!(matches!(truncated, KeystoneError::InvalidCertificate(_)));

    let mut extended = der.to_vec();
    extended.push(0x00);
    let trailing = ParsedCertificate::from_der(&extended)
        .unwrap_err()
        .to_string();
    assert!(trailing.contains("trailing"), "{trailing}");

    assert!(ParsedCertificate::from_der(b"not a certificate").is_err());
    assert!(ParsedCertificate::from_pem("-----BEGIN CERTIFICATE-----\nnope\n").is_err());
}

#[test]
fn a_pem_bundle_of_the_wrong_length_is_refused() {
    // `from_pem` requires exactly one certificate: a bundle silently taking the
    // first entry would let a chain file be installed as a leaf.
    let both = format!("{}{}", fixture("device.pem"), fixture("ca.pem"));
    let error = ParsedCertificate::from_pem(&both).unwrap_err().to_string();
    assert!(error.contains("found 2"), "{error}");

    let bundle = ParsedCertificate::from_pem_bundle(&both).expect("a bundle parses");
    assert_eq!(bundle.len(), 2);
    assert_eq!(bundle[0].subject, certificate("device.pem").subject);
}

#[test]
fn a_private_key_pem_is_not_accepted_as_a_certificate() {
    let error = ParsedCertificate::from_pem(&fixture("device-key.pem"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("PRIVATE KEY") || error.contains("expected"),
        "{error}"
    );
}

#[test]
fn no_ca_private_key_exists_in_the_fixture_tree() {
    // The fixtures mirror the ephemeral CA: `generate.sh` deletes the issuing
    // keys, so nothing in the repository can mint a new certificate for an
    // arbitrary key under either fixture anchor. The device keys are private by
    // design — they stand in for the Secure Enclave — so they are exempt.
    let allowed_private_keys = ["device-key.pem", "other-device-key.pem"];

    for entry in std::fs::read_dir(fixtures_dir()).expect("the fixture directory is readable") {
        let entry = entry.expect("a readable directory entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if !entry.path().is_file() {
            continue;
        }
        let contents = std::fs::read_to_string(entry.path()).unwrap_or_default();
        let has_private_key = contents.contains("PRIVATE KEY-----");
        if allowed_private_keys.contains(&name.as_str()) {
            assert!(
                has_private_key,
                "{name} should hold the stand-in device key"
            );
            continue;
        }
        assert!(
            !has_private_key,
            "{name} contains private key material; a CA key must not survive generation"
        );
        assert!(
            !name.contains("ca-key") && !name.contains("ca_key"),
            "{name} looks like a CA private key"
        );
    }
}

#[test]
fn the_fixture_serial_survives_a_der_round_trip() {
    // The serial reaches AWS as the credential field, so re-parsing must not
    // renormalize it. Large serials are where a signed/unsigned mistake shows up.
    let leaf = certificate("device.pem");
    let round_tripped = ParsedCertificate::from_der(leaf.der()).expect("re-parses");
    assert_eq!(round_tripped.serial_decimal, leaf.serial_decimal);
    assert_eq!(
        leaf.serial_decimal,
        keystone_tests::FIXTURE_LEAF_SERIAL_DECIMAL
    );
    assert!(
        leaf.serial_decimal.parse::<u64>().unwrap() > u32::MAX as u64,
        "the fixture serial exceeds 32 bits on purpose"
    );
}

#[test]
fn a_ca_certificate_handed_to_enroll_install_is_described_as_a_ca() {
    // Ordering matters for the message: the CA check runs before the key-usage
    // check, so a user who installs `ca.pem` by mistake is told it is a CA rather
    // than that it cannot sign.
    let error = validate_device_certificate(&certificate("ca.pem"), &ValidationContext::new(NOW))
        .unwrap_err()
        .to_string();
    assert!(error.contains("CA certificate"), "{error}");
}
