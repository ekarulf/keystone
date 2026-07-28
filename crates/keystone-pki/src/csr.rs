//! PKCS#10 certificate signing requests.
//!
//! `keystone enroll csr` produces one of these for an existing CA. The Secure
//! Enclave signs the `CertificationRequestInfo`, so the request proves possession
//! of the key without the key leaving the device.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::signer::KeystoneSigningIdentity;
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey};

use crate::certificate::encode_pem;
use crate::params::DeviceCertificateSpec;

/// PEM label for a certificate request.
const PEM_LABEL: &str = "CERTIFICATE REQUEST";

/// A generated CSR, already verified against its own public key.
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    der: Vec<u8>,
}

impl CertificateRequest {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn to_pem(&self) -> String {
        encode_pem(PEM_LABEL, &self.der)
    }
}

/// Adapts a Keystone signing identity to rcgen's signing interface.
///
/// This is the bridge that lets the Secure Enclave sign a PKCS#10 request:
/// rcgen builds the DER to be signed and calls back here, and the signature comes
/// out of the enclave. `PKCS_ECDSA_P256_SHA256` maps to ring's
/// `ECDSA_P256_SHA256_ASN1_SIGNING`, so rcgen expects DER — which is what
/// [`KeystoneSigningIdentity`] returns.
struct RemoteSigner<'a, I> {
    identity: &'a I,
    public_key_sec1: [u8; 65],
}

impl<I: KeystoneSigningIdentity> PublicKeyData for RemoteSigner<'_, I> {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_sec1
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl<I: KeystoneSigningIdentity> SigningKey for RemoteSigner<'_, I> {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        self.identity
            .sign_message_ecdsa_sha256(message)
            // rcgen's error type cannot carry a cause, so the specific enclave
            // failure is reported by `create_signing_request`'s own error path
            // when it retries the signature for verification.
            .map(|signature| signature.into_bytes())
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

/// Build and self-verify a PKCS#10 CSR for a device.
///
/// The signature is checked before the request is returned: an enclave that
/// produced a bad signature should fail here, not when the CA rejects the file
/// days later.
pub fn create_signing_request<I: KeystoneSigningIdentity>(
    identity: &I,
    spec: &DeviceCertificateSpec,
) -> Result<CertificateRequest> {
    let public_key_sec1 = identity.public_key_sec1()?;
    let params = spec.to_csr_params()?;

    // Confirm the enclave is usable before rcgen swallows the error: rcgen's
    // callback cannot carry a cause, so a failure inside `serialize_request`
    // would arrive as a bare "remote key error".
    identity.sign_message_ecdsa_sha256(b"keystone csr signer probe")?;

    let signer = RemoteSigner {
        identity,
        public_key_sec1,
    };
    let request = params.serialize_request(&signer).map_err(|e| match e {
        rcgen::Error::RemoteKeyError => KeystoneError::SecureEnclave(
            "the signing key refused to sign the certificate request".to_string(),
        ),
        other => KeystoneError::Other(format!("cannot build the certificate request: {other}")),
    })?;
    let der = request.der().to_vec();

    verify_request(&der)?;
    Ok(CertificateRequest { der })
}

/// Verify a CSR's signature against the public key it carries.
pub fn verify_request(der: &[u8]) -> Result<()> {
    use x509_parser::prelude::FromDer as _;

    let (rest, request) = x509_parser::certification_request::X509CertificationRequest::from_der(
        der,
    )
    .map_err(|e| KeystoneError::Other(format!("cannot parse the certificate request: {e}")))?;
    if !rest.is_empty() {
        return Err(KeystoneError::Other(format!(
            "{} trailing bytes after the certificate request",
            rest.len()
        )));
    }
    request.verify_signature().map_err(|e| {
        KeystoneError::Other(format!("the certificate request does not self-verify: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, TEST_NOW};
    use keystone_core::identity::KeyId;

    #[test]
    fn a_request_is_signed_by_the_device_key_and_self_verifies() {
        let key = testing::random_device_key();
        let spec = DeviceCertificateSpec::new("erik-macbook", key.key_id().clone(), TEST_NOW);
        let request = create_signing_request(&key, &spec).unwrap();

        // `verify_request` already ran inside the constructor; run it again on
        // the returned bytes so the file that gets written is what was checked.
        verify_request(request.der()).unwrap();
    }

    #[test]
    fn a_request_carries_the_device_public_key_and_uri_san() {
        use x509_parser::prelude::FromDer as _;

        let key = testing::random_device_key();
        let spec = DeviceCertificateSpec::new("erik-macbook", key.key_id().clone(), TEST_NOW);
        let request = create_signing_request(&key, &spec).unwrap();

        let (_, parsed) =
            x509_parser::certification_request::X509CertificationRequest::from_der(request.der())
                .unwrap();
        let info = &parsed.certification_request_info;
        assert_eq!(
            info.subject_pki.subject_public_key.as_ref(),
            key.public_key_sec1().as_slice()
        );
        assert!(info.subject.to_string().contains("erik-macbook"));

        let rendered = format!("{:?}", info.attributes());
        assert!(
            rendered.contains(&key.key_id().device_san_uri()),
            "device SAN missing from {rendered}"
        );
    }

    #[test]
    fn a_request_round_trips_through_pem() {
        let key = testing::random_device_key();
        let spec = DeviceCertificateSpec::new("erik-macbook", key.key_id().clone(), TEST_NOW);
        let request = create_signing_request(&key, &spec).unwrap();

        let pem = request.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(!pem.contains("PRIVATE KEY"));

        let decoded = {
            use base64::prelude::{Engine as _, BASE64_STANDARD};
            let body: String = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .collect();
            BASE64_STANDARD.decode(body).unwrap()
        };
        assert_eq!(decoded, request.der());
    }

    #[test]
    fn a_corrupted_request_does_not_verify() {
        let key = testing::random_device_key();
        let spec = DeviceCertificateSpec::new("erik-macbook", key.key_id().clone(), TEST_NOW);
        let request = create_signing_request(&key, &spec).unwrap();

        // Flip a byte in the middle of the signed body.
        let mut der = request.der().to_vec();
        let midpoint = der.len() / 2;
        der[midpoint] ^= 0xff;
        assert!(verify_request(&der).is_err());
    }

    #[test]
    fn trailing_bytes_after_a_request_are_refused() {
        let key = testing::random_device_key();
        let spec = DeviceCertificateSpec::new("erik-macbook", key.key_id().clone(), TEST_NOW);
        let request = create_signing_request(&key, &spec).unwrap();

        let mut der = request.der().to_vec();
        der.push(0);
        let error = verify_request(&der).unwrap_err();
        assert!(error.to_string().contains("trailing"), "{error}");
    }

    #[test]
    fn a_signer_that_fails_produces_a_secure_enclave_error() {
        // If the enclave cannot sign, enrollment must fail closed rather than
        // emitting an unsigned or partially signed request.
        struct BrokenSigner {
            key_id: KeyId,
            public_key: [u8; 65],
        }
        impl KeystoneSigningIdentity for BrokenSigner {
            fn key_id(&self) -> &KeyId {
                &self.key_id
            }
            fn public_key_sec1(&self) -> Result<[u8; 65]> {
                Ok(self.public_key)
            }
            fn sign_message_ecdsa_sha256(
                &self,
                _message: &[u8],
            ) -> Result<keystone_core::signer::DerEcdsaSignature> {
                Err(KeystoneError::SecureEnclave(
                    "key is not available".to_string(),
                ))
            }
        }

        let real = testing::random_device_key();
        let signer = BrokenSigner {
            key_id: real.key_id().clone(),
            public_key: real.public_key_sec1(),
        };
        let spec = DeviceCertificateSpec::new("erik-macbook", real.key_id().clone(), TEST_NOW);
        let error = create_signing_request(&signer, &spec).unwrap_err();
        assert!(matches!(error, KeystoneError::SecureEnclave(_)), "{error}");
    }

    #[test]
    fn an_invalid_subject_is_refused_before_the_key_is_used() {
        let key = testing::random_device_key();
        let mut spec = DeviceCertificateSpec::new("erik-macbook", key.key_id().clone(), TEST_NOW);
        spec.device_name = "bad\nname".to_string();
        assert!(matches!(
            create_signing_request(&key, &spec),
            Err(KeystoneError::InvalidConfiguration(_))
        ));
    }
}
