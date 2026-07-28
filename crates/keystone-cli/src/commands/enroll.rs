//! `keystone enroll csr|install` — enrollment with an existing CA.
//!
//! The alternative to `keystone bootstrap` for an installation that already runs
//! a CA. `csr` asks the enclave to sign a PKCS#10 request; `install` records the
//! certificate that comes back, refusing one that does not belong to the key.

use std::path::Path;

use keystone_core::error::{KeystoneError, Result};
use keystone_core::identity::KeyId;
use keystone_core::signer::KeystoneSigningIdentity as _;
use keystone_core::store::write_atomic;
use keystone_pki::{DeviceCertificateSpec, ParsedCertificate};

use crate::cli::{EnrollCommand, EnrollCsrArgs, EnrollInstallArgs};
use crate::context::Context;

pub fn run(context: &Context, command: &EnrollCommand) -> Result<()> {
    match command {
        EnrollCommand::Csr(args) => csr(context, args),
        EnrollCommand::Install(args) => install(context, args),
    }
}

fn csr(context: &Context, args: &EnrollCsrArgs) -> Result<()> {
    let profile = context.load_profile(&args.profile)?;
    let key_id = context.require_key_id(&args.profile, &profile)?;
    let now = context.now_checked()?;

    let expected_san = key_id.device_san_uri();
    if let Some(requested) = &args.san_uri {
        // The deployed trust policy conditions on this exact URI, so a request for
        // a different one produces a certificate that cannot authenticate.
        if requested != &expected_san {
            return Err(KeystoneError::InvalidConfiguration(format!(
                "--san-uri {requested:?} does not match this profile's device URI {expected_san:?}. \
                 The trust policy authorizes the profile's URI, so a certificate carrying another \
                 one would be rejected by AWS."
            )));
        }
    }

    let device_name = device_name(args, &key_id)?;
    let key = crate::identity::load_key(&context.store, &args.profile, &profile)?;

    // Validity is a CA decision for an external enrollment; the CSR carries a
    // nominal window so the parameters are well formed.
    let spec = DeviceCertificateSpec::new(device_name, key_id.clone(), now)
        .with_organization(organization(args))
        .with_validity(now, now + time::Duration::days(365));

    let request = keystone_pki::create_signing_request(&key, &spec)?;
    write_atomic(&args.output, request.to_pem().as_bytes())?;

    context.note(format!(
        "Wrote a certificate signing request to {}",
        args.output.display()
    ));
    context.note(format!("Subject: {}", subject_summary(&spec)));
    context.note(format!("Requested URI SAN: {expected_san}"));
    context.note(format!(
        "Public-key fingerprint: {}",
        keystone_core::identity::Sha256Fingerprint::of(&key.public_key_sec1()?).display_short()
    ));
    context.note("");
    context.note("Have your CA issue an end-entity certificate with:");
    context.note("  - keyUsage: digitalSignature (critical)");
    context.note("  - basicConstraints: CA=false (critical)");
    context.note(format!("  - subjectAltName: URI={expected_san}"));
    context.note("");
    context.note("Then install it:");
    context.note(format!(
        "    keystone enroll install --profile {} --certificate leaf.pem --chain issuer.pem",
        args.profile
    ));
    Ok(())
}

/// The device name for the subject, from `--subject`, `--device-name`, or the key.
fn device_name(args: &EnrollCsrArgs, key_id: &KeyId) -> Result<String> {
    if let Some(subject) = &args.subject {
        return field(subject, "CN").ok_or_else(|| {
            KeystoneError::InvalidConfiguration(format!(
                "--subject {subject:?} has no CN=. A subject looks like \
                 \"CN=erik-macbook,OU=Keystone Devices,O=Example\"."
            ))
        });
    }
    if let Some(name) = &args.device_name {
        return Ok(name.clone());
    }
    // Better than failing: the key id is unique and identifies the device in the
    // CA's records, and the user can always pass a friendlier name.
    Ok(format!("keystone-{}", key_id.short()))
}

fn organization(args: &EnrollCsrArgs) -> Option<String> {
    args.subject
        .as_deref()
        .and_then(|subject| field(subject, "O"))
}

/// Pull one RDN out of a comma-separated subject string.
fn field(subject: &str, key: &str) -> Option<String> {
    subject.split(',').find_map(|part| {
        let (name, value) = part.split_once('=')?;
        (name.trim().eq_ignore_ascii_case(key)).then(|| value.trim().to_string())
    })
}

fn subject_summary(spec: &DeviceCertificateSpec) -> String {
    match &spec.organization {
        Some(organization) => format!(
            "CN={}, OU=Keystone Devices, O={organization}",
            spec.device_name
        ),
        None => format!("CN={}, OU=Keystone Devices", spec.device_name),
    }
}

fn install(context: &Context, args: &EnrollInstallArgs) -> Result<()> {
    let mut config = context.load_config()?;
    let profile = config.profile(&args.profile)?.clone();
    let key_id = context.require_key_id(&args.profile, &profile)?;
    let now = context.now_checked()?;

    let leaf = read_certificate(&args.certificate)?;
    let chain = read_bundle(&args.chain)?;
    let (anchor, intermediates) = split_chain(chain, &leaf)?;

    // Validate before recording: the full device-certificate check plus the chain,
    // so a certificate AWS would reject never becomes the profile's certificate.
    let key = crate::identity::load_key(&context.store, &args.profile, &profile)?;
    keystone_pki::validate_device_certificate(
        &leaf,
        &keystone_pki::ValidationContext::new(now)
            .expecting_key(key.public_key_sec1()?)
            .expecting_key_id(key_id.clone()),
    )?;
    keystone_pki::validate_chain(&leaf, &intermediates, &anchor, now)?;
    if anchor.not_after < leaf.not_after {
        context.note(
            "warning: the issuing CA expires before this certificate does, so the chain will \
             stop validating before the certificate expires",
        );
    }

    // Keystone stores exactly one issuer alongside the leaf, and it must be the
    // trust anchor AWS holds. An intermediate would have to travel in
    // `x-amz-x509-chain`, which the MVP does not carry.
    if !intermediates.is_empty() {
        return Err(KeystoneError::InvalidCertificateChain(format!(
            "the chain contains {} intermediate certificate(s). Keystone v1 registers the \
             issuing CA itself as the trust anchor, so supply a chain of exactly the issuing CA.",
            intermediates.len()
        )));
    }

    let fingerprint = leaf.fingerprint();
    context
        .store
        .save_certificates(&fingerprint, leaf.der(), anchor.der())?;

    let previous = profile.certificate_fingerprint_sha256.clone();
    let entry = config.profile_mut(&args.profile)?;
    entry.certificate_fingerprint_sha256 = Some(fingerprint.clone());
    entry.ca_fingerprint_sha256 = Some(anchor.fingerprint());
    entry.issuer = Some(keystone_core::config::IssuerMetadata {
        mode: keystone_core::config::IssuerMode::ExternalCa,
        // The CA still exists, so this certificate can be reissued from a new CSR.
        renewable: true,
        trust_anchor_rotation_required: false,
        certificate_expires_at: leaf.not_after,
    });
    context.save_config(&config)?;

    // Only after the new pair is committed: the old one was the fallback until
    // this point.
    if let Some(previous) = previous.filter(|previous| previous != &fingerprint) {
        context.detail(format!(
            "removing the previous certificate {}",
            previous.display_short()
        ));
        context.store.delete_certificates(&previous)?;
    }

    context.note(format!(
        "Installed certificate for profile {}",
        args.profile
    ));
    context.note(format!("Subject: {}", leaf.subject));
    context.note(format!("Issuer: {}", leaf.issuer));
    context.note(format!("Serial: {}", leaf.serial_decimal));
    context.note(format!(
        "Expires: {}",
        keystone_core::time::format_rfc3339(leaf.not_after)
    ));
    context.note(format!("Fingerprint: {}", fingerprint.display_short()));
    context.note("");
    context.note("Next:");
    context.note(format!(
        "    keystone infra cdk init --profile {} --output ./keystone-infra",
        args.profile
    ));
    context.note(format!("    keystone test --profile {}", args.profile));
    Ok(())
}

/// Read one certificate, accepting PEM or DER.
fn read_certificate(path: &Path) -> Result<ParsedCertificate> {
    let bytes = std::fs::read(path)
        .map_err(|error| KeystoneError::io(format!("cannot read {}", path.display()), error))?;
    match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
            ParsedCertificate::from_pem(text)
        }
        _ => ParsedCertificate::from_der(&bytes),
    }
}

/// Read a PEM bundle, or a single DER certificate.
fn read_bundle(path: &Path) -> Result<Vec<ParsedCertificate>> {
    let bytes = std::fs::read(path)
        .map_err(|error| KeystoneError::io(format!("cannot read {}", path.display()), error))?;
    match std::str::from_utf8(&bytes) {
        Ok(text) if text.contains("-----BEGIN CERTIFICATE-----") => {
            ParsedCertificate::from_pem_bundle(text)
        }
        _ => Ok(vec![ParsedCertificate::from_der(&bytes)?]),
    }
}

/// Separate the self-issued anchor from the intermediates, dropping a repeated leaf.
///
/// `--chain` is commonly the same bundle the CA hands out, which often begins
/// with the leaf. Accepting that is friendlier than rejecting it, as long as the
/// duplicate is removed rather than treated as an intermediate.
fn split_chain(
    chain: Vec<ParsedCertificate>,
    leaf: &ParsedCertificate,
) -> Result<(ParsedCertificate, Vec<ParsedCertificate>)> {
    let leaf_fingerprint = leaf.fingerprint();
    let mut issuers: Vec<ParsedCertificate> = chain
        .into_iter()
        .filter(|certificate| certificate.fingerprint() != leaf_fingerprint)
        .collect();

    if issuers.is_empty() {
        return Err(KeystoneError::InvalidCertificateChain(
            "the chain file contains no issuing certificate".to_string(),
        ));
    }

    let anchor_index = issuers
        .iter()
        .position(ParsedCertificate::is_self_issued)
        .ok_or_else(|| {
            KeystoneError::InvalidCertificateChain(
                "the chain does not contain a self-issued root, so it does not terminate in a \
                 trust anchor"
                    .to_string(),
            )
        })?;
    let anchor = issuers.remove(anchor_index);
    Ok((anchor, issuers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subject_string_yields_the_common_name_and_organization() {
        let args = EnrollCsrArgs {
            profile: "personal".to_string(),
            subject: Some("CN=erik-macbook,OU=Keystone Devices,O=Karulf".to_string()),
            device_name: None,
            san_uri: None,
            output: std::path::PathBuf::from("out.csr"),
        };
        let key_id = KeyId::generate();
        assert_eq!(device_name(&args, &key_id).unwrap(), "erik-macbook");
        assert_eq!(organization(&args).as_deref(), Some("Karulf"));
    }

    #[test]
    fn a_subject_without_a_common_name_is_refused_with_an_example() {
        let args = EnrollCsrArgs {
            profile: "personal".to_string(),
            subject: Some("OU=Keystone Devices".to_string()),
            device_name: None,
            san_uri: None,
            output: std::path::PathBuf::from("out.csr"),
        };
        let error = device_name(&args, &KeyId::generate()).unwrap_err();
        assert!(format!("{error}").contains("CN=erik-macbook"), "{error}");
    }

    #[test]
    fn a_device_name_falls_back_to_the_key_id() {
        // So `keystone enroll csr` works with no naming flags at all.
        let args = EnrollCsrArgs {
            profile: "personal".to_string(),
            subject: None,
            device_name: None,
            san_uri: None,
            output: std::path::PathBuf::from("out.csr"),
        };
        let key_id = KeyId::generate();
        let name = device_name(&args, &key_id).unwrap();
        assert!(name.starts_with("keystone-"), "{name}");
        assert!(organization(&args).is_none());
    }
}
