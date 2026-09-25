//! Compact ES256 service tokens signed by an existing Keystone device key.

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use keystone_core::error::{KeystoneError, Result};
use keystone_core::signer::KeystoneSigningIdentity;
use serde::Serialize;
use time::OffsetDateTime;

use crate::der_to_raw;

pub struct TokenClaims<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct Payload<'a> {
    iss: &'a str,
    sub: String,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

/// Issue a compact JWT. The signing trait hashes the JWS signing input with SHA-256.
pub fn issue_es256_token(
    signer: &impl KeystoneSigningIdentity,
    claims: &TokenClaims<'_>,
) -> Result<String> {
    if claims.expires_at <= claims.issued_at {
        return Err(KeystoneError::InvalidConfiguration(
            "token expiry must be after issue time".into(),
        ));
    }
    let header = Header {
        alg: "ES256",
        typ: "JWT",
        kid: signer.key_id().as_str(),
    };
    let payload = Payload {
        iss: claims.issuer,
        sub: signer.key_id().device_san_uri(),
        aud: claims.audience,
        iat: claims.issued_at.unix_timestamp(),
        exp: claims.expires_at.unix_timestamp(),
    };
    let encode = |value: &[u8]| BASE64_URL_SAFE_NO_PAD.encode(value);
    let header = serde_json::to_vec(&header)
        .map_err(|error| KeystoneError::Other(format!("cannot encode JWT header: {error}")))?;
    let payload = serde_json::to_vec(&payload)
        .map_err(|error| KeystoneError::Other(format!("cannot encode JWT claims: {error}")))?;
    let signing_input = format!("{}.{}", encode(&header), encode(&payload));
    let der = signer.sign_message_ecdsa_sha256(signing_input.as_bytes())?;
    let raw = der_to_raw(der.as_bytes())?;
    Ok(format!("{signing_input}.{}", encode(&raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDeviceKey;
    use keystone_core::identity::KeyId;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};

    #[test]
    fn token_has_expected_claims_and_verifiable_raw_signature() {
        let key = TestDeviceKey::generate(KeyId::parse("test-key").unwrap());
        let issued_at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_790_294_400);
        let token = issue_es256_token(
            &key,
            &TokenClaims {
                issuer: "https://auth.example.com/issuer",
                audience: "https://api.example.com/",
                issued_at,
                expires_at: issued_at + time::Duration::minutes(5),
            },
        )
        .unwrap();
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let decode = |s: &str| BASE64_URL_SAFE_NO_PAD.decode(s).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(
            header,
            serde_json::json!({"alg":"ES256","typ":"JWT","kid":"test-key"})
        );
        assert_eq!(
            payload,
            serde_json::json!({
                "iss":"https://auth.example.com/issuer",
                "sub":"urn:keystone:device:test-key",
                "aud":"https://api.example.com/",
                "iat":1_790_294_400,
                "exp":1_790_294_700
            })
        );
        let signature_bytes = decode(parts[2]);
        assert_eq!(signature_bytes.len(), 64);
        let signature = Signature::from_slice(&signature_bytes).unwrap();
        let verifier = VerifyingKey::from_sec1_bytes(&key.public_key_sec1()).unwrap();
        verifier
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();

        for index in 0..3 {
            let mut modified = parts
                .iter()
                .map(|part| (*part).to_string())
                .collect::<Vec<_>>();
            let first = modified[index].as_bytes()[0];
            modified[index].replace_range(..1, if first == b'A' { "B" } else { "A" });
            let tampered = format!("{}.{}", modified[0], modified[1]);
            let tampered_signature = decode(&modified[2]);
            let valid = Signature::from_slice(&tampered_signature)
                .ok()
                .is_some_and(|sig| verifier.verify(tampered.as_bytes(), &sig).is_ok());
            assert!(!valid, "tampering segment {index} must fail verification");
        }
    }
}
