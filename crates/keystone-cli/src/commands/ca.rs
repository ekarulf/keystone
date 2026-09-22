//! `keystone ca init|issue` — a reusable CA whose private key stays in AWS KMS.

use std::path::Path;
use std::sync::Mutex;

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::store::write_atomic;
use p256::ecdsa::signature::Verifier as _;
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey};

use crate::cli::{CaInitArgs, CaIssueArgs, KmsArgs};
use crate::commands::read_certificate;
use crate::context::{parse_validity, Context};

pub fn init(context: &Context, args: &CaInitArgs) -> Result<()> {
    let now = context.now_checked()?;
    let validity = parse_validity(&args.validity)?;
    let spec = keystone_pki::ExternalCaSpec::from_subject(&args.subject, now)?
        .with_validity(now, now + validity);
    let operations = AwsKmsOperations::new(&args.kms)?;
    let signer = KmsSigningKey::load(operations, args.kms.kms_key.clone())?;
    let certificate = signing_result(&signer, keystone_pki::initialize_ca(&signer, &spec, now))?;
    write_atomic(&args.output, certificate.to_pem().as_bytes())?;
    context.note(format!(
        "Created KMS-backed CA certificate at {}",
        args.output.display()
    ));
    context.note(format!("Subject: {}", certificate.subject));
    context.note(format!(
        "Fingerprint: {}",
        certificate.fingerprint().display_short()
    ));
    Ok(())
}

pub fn issue(context: &Context, args: &CaIssueArgs) -> Result<()> {
    let now = context.now_checked()?;
    let validity = parse_validity(&args.validity)?;
    let ca = read_certificate(&args.ca_certificate)?;
    let csr = read_csr(&args.csr)?;
    let operations = AwsKmsOperations::new(&args.kms)?;
    let signer = KmsSigningKey::load(operations, args.kms.kms_key.clone())?;
    let certificate = signing_result(
        &signer,
        keystone_pki::issue_certificate(&signer, &ca, &csr, now, now + validity),
    )?;
    write_atomic(&args.output, certificate.to_pem().as_bytes())?;
    context.note(format!(
        "Issued device certificate at {}",
        args.output.display()
    ));
    context.note(format!("Subject: {}", certificate.subject));
    context.note(format!("Serial: {}", certificate.serial_decimal));
    context.note(format!(
        "Expires: {}",
        keystone_core::time::format_rfc3339(certificate.not_after)
    ));
    Ok(())
}

fn read_csr(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .map_err(|error| KeystoneError::io(format!("cannot read {}", path.display()), error))?;
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(bytes);
    };
    if !text.contains("-----BEGIN ") {
        return Ok(bytes);
    }
    Ok(keystone_pki::CertificateRequest::from_pem(text)?
        .der()
        .to_vec())
}

#[derive(Clone)]
struct KmsKeyInfo {
    public_key_spki: Vec<u8>,
    key_spec: Option<KeySpec>,
    key_usage: Option<KeyUsageType>,
    signing_algorithms: Vec<SigningAlgorithmSpec>,
}

trait KmsOperations {
    fn get_public_key(&self, key_id: &str) -> Result<KmsKeyInfo>;
    fn sign_raw_ecdsa_sha256(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>>;
}

struct AwsKmsOperations {
    runtime: tokio::runtime::Runtime,
    client: aws_sdk_kms::Client,
}

impl AwsKmsOperations {
    fn new(args: &KmsArgs) -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| KeystoneError::Other(format!("cannot start AWS runtime: {e}")))?;
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(args.region.clone()));
        if let Some(profile) = &args.aws_profile {
            loader = loader.profile_name(profile);
        }
        let config = runtime.block_on(loader.load());
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Self { runtime, client })
    }
}

impl KmsOperations for AwsKmsOperations {
    fn get_public_key(&self, key_id: &str) -> Result<KmsKeyInfo> {
        let output = self
            .runtime
            .block_on(self.client.get_public_key().key_id(key_id).send())
            .map_err(|e| KeystoneError::Network(format!("KMS GetPublicKey failed: {e}")))?;
        let public_key_spki = output
            .public_key()
            .ok_or_else(|| {
                KeystoneError::InvalidConfiguration(
                    "KMS GetPublicKey returned no public key".to_string(),
                )
            })?
            .as_ref()
            .to_vec();
        Ok(KmsKeyInfo {
            public_key_spki,
            key_spec: output.key_spec().cloned(),
            key_usage: output.key_usage().cloned(),
            signing_algorithms: output.signing_algorithms().to_vec(),
        })
    }

    fn sign_raw_ecdsa_sha256(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let output = self
            .runtime
            .block_on(
                self.client
                    .sign()
                    .key_id(key_id)
                    .message(Blob::new(message))
                    .message_type(MessageType::Raw)
                    .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                    .send(),
            )
            .map_err(|e| KeystoneError::Network(format!("KMS Sign failed: {e}")))?;
        output
            .signature()
            .map(|signature| signature.as_ref().to_vec())
            .ok_or_else(|| KeystoneError::Other("KMS Sign returned no signature".to_string()))
    }
}

struct KmsSigningKey<O> {
    operations: O,
    key_id: String,
    public_key_sec1: [u8; 65],
    verifying_key: p256::ecdsa::VerifyingKey,
    signing_error: Mutex<Option<KeystoneError>>,
}

impl<O: KmsOperations> KmsSigningKey<O> {
    fn load(operations: O, key_id: String) -> Result<Self> {
        let info = operations.get_public_key(&key_id)?;
        let public_key_sec1 = validate_kms_key_info(&info)?;
        let verifying_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key_sec1).map_err(|e| {
                KeystoneError::InvalidConfiguration(format!("KMS public key is invalid: {e}"))
            })?;
        Ok(Self {
            operations,
            key_id,
            public_key_sec1,
            verifying_key,
            signing_error: Mutex::new(None),
        })
    }

    fn take_signing_error(&self) -> Option<KeystoneError> {
        self.signing_error.lock().ok()?.take()
    }
}

impl<O: KmsOperations> PublicKeyData for KmsSigningKey<O> {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_sec1
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl<O: KmsOperations> SigningKey for KmsSigningKey<O> {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        let der = self
            .operations
            .sign_raw_ecdsa_sha256(&self.key_id, message)
            .map_err(|error| {
                if let Ok(mut slot) = self.signing_error.lock() {
                    *slot = Some(error);
                }
                rcgen::Error::RemoteKeyError
            })?;
        let signature = p256::ecdsa::Signature::from_der(&der).map_err(|_| {
            if let Ok(mut slot) = self.signing_error.lock() {
                *slot = Some(KeystoneError::Other(
                    "KMS returned a malformed DER ECDSA signature".to_string(),
                ));
            }
            rcgen::Error::RemoteKeyError
        })?;
        // Verification is deliberately over the raw rcgen callback bytes. The
        // verifier hashes once, exactly as KMS RAW does, and therefore rejects
        // a KMS adapter that accidentally submitted SHA256(message) as RAW.
        self.verifying_key
            .verify(message, &signature)
            .map_err(|_| {
                if let Ok(mut slot) = self.signing_error.lock() {
                    *slot = Some(KeystoneError::Other(
                        "KMS signature did not verify against its public key and the raw message"
                            .to_string(),
                    ));
                }
                rcgen::Error::RemoteKeyError
            })?;
        Ok(der)
    }
}

fn signing_result<O: KmsOperations, T>(signer: &KmsSigningKey<O>, result: Result<T>) -> Result<T> {
    result.map_err(|error| signer.take_signing_error().unwrap_or(error))
}

fn validate_kms_key_info(info: &KmsKeyInfo) -> Result<[u8; 65]> {
    if info.key_usage.as_ref() != Some(&KeyUsageType::SignVerify) {
        return Err(KeystoneError::InvalidConfiguration(
            "KMS key usage must be SIGN_VERIFY".to_string(),
        ));
    }
    if info.key_spec.as_ref() != Some(&KeySpec::EccNistP256) {
        return Err(KeystoneError::InvalidConfiguration(
            "KMS key spec must be ECC_NIST_P256".to_string(),
        ));
    }
    if !info
        .signing_algorithms
        .contains(&SigningAlgorithmSpec::EcdsaSha256)
    {
        return Err(KeystoneError::InvalidConfiguration(
            "KMS key must support ECDSA_SHA_256".to_string(),
        ));
    }
    let spki = rcgen::SubjectPublicKeyInfo::from_der(&info.public_key_spki).map_err(|e| {
        KeystoneError::InvalidConfiguration(format!("KMS public key SPKI is malformed: {e}"))
    })?;
    if spki.algorithm() != &rcgen::PKCS_ECDSA_P256_SHA256 {
        return Err(KeystoneError::InvalidConfiguration(
            "KMS public key SPKI is not P-256".to_string(),
        ));
    }
    let point: [u8; 65] = spki.der_bytes().try_into().map_err(|_| {
        KeystoneError::InvalidConfiguration(
            "KMS P-256 public key is not an uncompressed SEC1 point".to_string(),
        )
    })?;
    p256::PublicKey::from_sec1_bytes(&point).map_err(|e| {
        KeystoneError::InvalidConfiguration(format!("KMS P-256 public key is invalid: {e}"))
    })?;
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use std::sync::Arc;

    struct TestPublicKey([u8; 65]);

    impl PublicKeyData for TestPublicKey {
        fn der_bytes(&self) -> &[u8] {
            &self.0
        }

        fn algorithm(&self) -> &'static SignatureAlgorithm {
            &rcgen::PKCS_ECDSA_P256_SHA256
        }
    }

    fn signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::random(&mut rand::thread_rng())
    }

    fn valid_info(key: &p256::ecdsa::SigningKey) -> KmsKeyInfo {
        let point: [u8; 65] = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        KmsKeyInfo {
            public_key_spki: TestPublicKey(point).subject_public_key_info(),
            key_spec: Some(KeySpec::EccNistP256),
            key_usage: Some(KeyUsageType::SignVerify),
            signing_algorithms: vec![SigningAlgorithmSpec::EcdsaSha256],
        }
    }

    struct FakeOperations {
        key: p256::ecdsa::SigningKey,
        info: KmsKeyInfo,
        messages: Arc<Mutex<Vec<Vec<u8>>>>,
        malformed_signature: bool,
        double_hash: bool,
    }

    impl KmsOperations for FakeOperations {
        fn get_public_key(&self, _key_id: &str) -> Result<KmsKeyInfo> {
            Ok(self.info.clone())
        }

        fn sign_raw_ecdsa_sha256(&self, _key_id: &str, message: &[u8]) -> Result<Vec<u8>> {
            self.messages.lock().unwrap().push(message.to_vec());
            if self.malformed_signature {
                return Ok(vec![1, 2, 3]);
            }
            let digest;
            let signed = if self.double_hash {
                use sha2::Digest as _;
                digest = sha2::Sha256::digest(message);
                digest.as_slice()
            } else {
                message
            };
            let signature: p256::ecdsa::Signature = self.key.sign(signed);
            Ok(signature.to_der().as_bytes().to_vec())
        }
    }

    #[test]
    fn valid_kms_metadata_and_spki_are_accepted() {
        let key = signing_key();
        assert_eq!(
            validate_kms_key_info(&valid_info(&key)).unwrap().as_slice(),
            key.verifying_key().to_encoded_point(false).as_bytes()
        );
    }

    #[test]
    fn incompatible_kms_metadata_is_rejected() {
        let key = signing_key();

        let mut info = valid_info(&key);
        info.key_spec = Some(KeySpec::Rsa2048);
        assert!(validate_kms_key_info(&info).is_err());

        let mut info = valid_info(&key);
        info.key_spec = Some(KeySpec::EccNistP384);
        assert!(validate_kms_key_info(&info).is_err());

        let mut info = valid_info(&key);
        info.key_usage = Some(KeyUsageType::EncryptDecrypt);
        assert!(validate_kms_key_info(&info).is_err());

        let mut info = valid_info(&key);
        info.signing_algorithms.clear();
        assert!(validate_kms_key_info(&info).is_err());
    }

    #[test]
    fn malformed_kms_spki_is_rejected() {
        let key = signing_key();
        let mut info = valid_info(&key);
        info.public_key_spki = vec![1, 2, 3];
        assert!(validate_kms_key_info(&info).is_err());
    }

    #[test]
    fn signing_passes_the_raw_message_without_double_hashing_and_accepts_der() {
        let key = signing_key();
        let messages = Arc::new(Mutex::new(Vec::new()));
        let operations = FakeOperations {
            info: valid_info(&key),
            key,
            messages: Arc::clone(&messages),
            malformed_signature: false,
            double_hash: false,
        };
        let signer = KmsSigningKey::load(operations, "test-key".to_string()).unwrap();
        let message = b"rcgen passes this exact message to KMS";
        let signature = signer.sign(message).unwrap();
        assert_eq!(&*messages.lock().unwrap(), &[message.to_vec()]);
        assert!(p256::ecdsa::Signature::from_der(&signature).is_ok());
    }

    #[test]
    fn a_double_hashed_signature_is_rejected() {
        let key = signing_key();
        let operations = FakeOperations {
            info: valid_info(&key),
            key,
            messages: Arc::new(Mutex::new(Vec::new())),
            malformed_signature: false,
            double_hash: true,
        };
        let signer = KmsSigningKey::load(operations, "test-key".to_string()).unwrap();
        assert_eq!(
            signer.sign(b"message").unwrap_err(),
            rcgen::Error::RemoteKeyError
        );
    }

    #[test]
    fn malformed_kms_signature_is_rejected() {
        let key = signing_key();
        let operations = FakeOperations {
            info: valid_info(&key),
            key,
            messages: Arc::new(Mutex::new(Vec::new())),
            malformed_signature: true,
            double_hash: false,
        };
        let signer = KmsSigningKey::load(operations, "test-key".to_string()).unwrap();
        assert_eq!(
            signer.sign(b"message").unwrap_err(),
            rcgen::Error::RemoteKeyError
        );
    }
}
