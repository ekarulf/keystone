//! Conversion between the two ECDSA signature encodings.
//!
//! CryptoKit returns a P-256 signature as `rawRepresentation`: the fixed-width
//! 64-byte `r || s`. X.509, PKCS#10, and the IAM Roles Anywhere authorization
//! header all want DER (`SEQUENCE { r INTEGER, s INTEGER }`). Getting this wrong
//! produces a signature AWS rejects with a message that says nothing about
//! encoding, so the conversion lives in one place with its own tests.

use keystone_core::error::{KeystoneError, Result};
use keystone_core::signer::DerEcdsaSignature;

/// Bytes in a P-256 scalar.
const SCALAR_LEN: usize = 32;

/// Bytes in a raw P-256 signature.
pub const RAW_SIGNATURE_LEN: usize = SCALAR_LEN * 2;

/// Convert a raw 64-byte `r || s` signature to DER.
pub fn raw_to_der(raw: &[u8]) -> Result<DerEcdsaSignature> {
    if raw.len() != RAW_SIGNATURE_LEN {
        return Err(KeystoneError::Other(format!(
            "raw P-256 signature must be {RAW_SIGNATURE_LEN} bytes, found {}",
            raw.len()
        )));
    }
    let (r, s) = raw.split_at(SCALAR_LEN);
    if is_zero(r) || is_zero(s) {
        // A zero scalar is never a valid ECDSA signature; encoding one would
        // hide a signer failure behind a remote rejection.
        return Err(KeystoneError::Other(
            "raw P-256 signature contains a zero scalar".to_string(),
        ));
    }

    let r = encode_integer(r);
    let s = encode_integer(s);
    let body_len = r.len() + s.len();
    // A P-256 signature body is always well under 128 bytes, so the DER length
    // is a single byte.
    debug_assert!(
        body_len < 128,
        "P-256 signature body fits in short-form DER"
    );

    let mut der = Vec::with_capacity(body_len + 2);
    der.push(0x30);
    der.push(u8::try_from(body_len).map_err(|_| {
        KeystoneError::Other("P-256 signature body is unexpectedly large".to_string())
    })?);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Ok(DerEcdsaSignature::from_der(der))
}

/// Convert a DER signature to the raw 64-byte form.
///
/// Used to verify a signature with an API that expects the raw encoding, and by
/// the round-trip tests.
pub fn der_to_raw(der: &[u8]) -> Result<[u8; RAW_SIGNATURE_LEN]> {
    let (r, s) = parse_der_pair(der)?;
    let mut raw = [0u8; RAW_SIGNATURE_LEN];
    place_scalar(&r, &mut raw[..SCALAR_LEN])?;
    place_scalar(&s, &mut raw[SCALAR_LEN..])?;
    Ok(raw)
}

/// Verify a DER ECDSA signature over `message` against a SEC1 public key.
///
/// The signature is checked against the message, not a digest: SHA-256 is applied
/// here, matching what [`keystone_core::signer::KeystoneSigningIdentity`] promises
/// and what CryptoKit's `signature(for:)` does internally. A caller that hashed
/// first would be hashing twice.
pub fn verify_der_signature(public_key_sec1: &[u8], message: &[u8], der: &[u8]) -> Result<()> {
    use p256::ecdsa::signature::Verifier as _;

    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|e| KeystoneError::Other(format!("public key is unusable: {e}")))?;
    let signature = p256::ecdsa::Signature::from_der(der)
        .map_err(|e| KeystoneError::Other(format!("signature is not valid DER ECDSA: {e}")))?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| KeystoneError::CertificateKeyMismatch)
}

/// Encode one scalar as a DER INTEGER.
///
/// DER integers are signed, so a leading byte of 0x80 or above needs a 0x00
/// prefix, and leading zero bytes are not permitted.
fn encode_integer(scalar: &[u8]) -> Vec<u8> {
    let trimmed = scalar.iter().position(|&b| b != 0).unwrap_or(scalar.len());
    let value = &scalar[trimmed..];
    let mut out = Vec::with_capacity(value.len() + 3);
    out.push(0x02);
    if value.is_empty() {
        out.push(1);
        out.push(0);
        return out;
    }
    let needs_pad = value[0] & 0x80 != 0;
    out.push(u8::try_from(value.len() + usize::from(needs_pad)).unwrap_or(u8::MAX));
    if needs_pad {
        out.push(0);
    }
    out.extend_from_slice(value);
    out
}

/// Extract the two INTEGER values from a DER ECDSA signature.
fn parse_der_pair(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let malformed =
        |reason: &str| KeystoneError::Other(format!("malformed DER ECDSA signature: {reason}"));

    let mut cursor = der;
    if cursor.first() != Some(&0x30) {
        return Err(malformed("expected a SEQUENCE"));
    }
    cursor = &cursor[1..];
    let (body_len, rest) = read_short_length(cursor).ok_or_else(|| malformed("bad length"))?;
    if rest.len() != body_len {
        return Err(malformed("length does not match the content"));
    }

    let (r, rest) = read_integer(rest).ok_or_else(|| malformed("bad r"))?;
    let (s, rest) = read_integer(rest).ok_or_else(|| malformed("bad s"))?;
    if !rest.is_empty() {
        return Err(malformed("trailing bytes"));
    }
    Ok((r, s))
}

fn read_short_length(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    // Only the short form is accepted: a P-256 signature never needs more.
    if first & 0x80 != 0 {
        return None;
    }
    Some((usize::from(first), rest))
}

fn read_integer(bytes: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x02 {
        return None;
    }
    let (len, rest) = read_short_length(rest)?;
    if len == 0 || rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    // Reject the negative and non-minimal encodings a strict DER parser would.
    if value[0] & 0x80 != 0 {
        return None;
    }
    if len > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return None;
    }
    Some((value.to_vec(), rest))
}

/// Right-align a scalar in a fixed-width slot.
fn place_scalar(value: &[u8], slot: &mut [u8]) -> Result<()> {
    let trimmed = value.iter().position(|&b| b != 0).unwrap_or(value.len());
    let value = &value[trimmed..];
    if value.len() > slot.len() {
        return Err(KeystoneError::Other(
            "DER ECDSA scalar is too large for P-256".to_string(),
        ));
    }
    let offset = slot.len() - value.len();
    slot[offset..].copy_from_slice(value);
    Ok(())
}

fn is_zero(scalar: &[u8]) -> bool {
    scalar.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer as _, Verifier as _};
    use p256::ecdsa::{Signature, SigningKey};

    fn raw(r: u8, s: u8) -> Vec<u8> {
        let mut raw = vec![0u8; RAW_SIGNATURE_LEN];
        raw[SCALAR_LEN - 1] = r;
        raw[RAW_SIGNATURE_LEN - 1] = s;
        raw
    }

    #[test]
    fn a_small_signature_encodes_as_two_minimal_integers() {
        let der = raw_to_der(&raw(1, 2)).unwrap();
        assert_eq!(
            der.as_bytes(),
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
    }

    #[test]
    fn a_high_bit_scalar_is_padded_so_it_is_not_read_as_negative() {
        let mut input = vec![0u8; RAW_SIGNATURE_LEN];
        input[0] = 0xff;
        input[SCALAR_LEN] = 0x80;
        let der = raw_to_der(&input).unwrap();
        // Each 32-byte scalar becomes 0x02, len 33, 0x00, then the value.
        assert_eq!(der.as_bytes()[0], 0x30);
        assert_eq!(&der.as_bytes()[2..5], &[0x02, 33, 0x00]);
    }

    #[test]
    fn a_full_width_signature_round_trips() {
        let mut input = vec![0u8; RAW_SIGNATURE_LEN];
        for (index, byte) in input.iter_mut().enumerate() {
            // Nonzero everywhere, with values on both sides of 0x80.
            *byte = u8::try_from(index).unwrap_or(1).wrapping_add(1);
        }
        let der = raw_to_der(&input).unwrap();
        assert_eq!(der_to_raw(der.as_bytes()).unwrap().to_vec(), input);
    }

    #[test]
    fn every_scalar_length_round_trips() {
        // Leading zeros in a scalar are dropped by DER and must be restored on
        // the way back, or the signature silently changes value.
        for leading_zeros in 0..SCALAR_LEN {
            let mut input = vec![0u8; RAW_SIGNATURE_LEN];
            input[leading_zeros] = 0x91;
            input[SCALAR_LEN + leading_zeros] = 0x07;
            let der = raw_to_der(&input).unwrap();
            assert_eq!(
                der_to_raw(der.as_bytes()).unwrap().to_vec(),
                input,
                "failed with {leading_zeros} leading zeros"
            );
        }
    }

    #[test]
    fn a_raw_signature_of_the_wrong_length_is_refused() {
        for length in [0, 63, 65, 128] {
            assert!(raw_to_der(&vec![1u8; length]).is_err(), "length {length}");
        }
    }

    #[test]
    fn a_zero_scalar_is_refused_rather_than_encoded() {
        // Would be rejected remotely with an unhelpful error.
        assert!(raw_to_der(&raw(0, 5)).is_err());
        assert!(raw_to_der(&raw(5, 0)).is_err());
        assert!(raw_to_der(&[0u8; RAW_SIGNATURE_LEN]).is_err());
    }

    #[test]
    fn conversion_agrees_with_an_independent_implementation() {
        // The p256 crate produces both encodings, so it can arbitrate.
        let key = SigningKey::random(&mut rand::thread_rng());
        for message in [b"".as_slice(), b"keystone", &[0u8; 1024]] {
            let signature: Signature = key.sign(message);
            let converted = raw_to_der(&signature.to_bytes()).unwrap();
            assert_eq!(
                converted.as_bytes(),
                signature.to_der().as_bytes(),
                "DER encodings differ"
            );
            assert_eq!(
                der_to_raw(signature.to_der().as_bytes()).unwrap().to_vec(),
                signature.to_bytes().to_vec(),
                "raw encodings differ"
            );
        }
    }

    #[test]
    fn a_converted_signature_still_verifies() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = *key.verifying_key();
        let message = b"keystone device certificate";
        let signature: Signature = key.sign(message);

        let der = raw_to_der(&signature.to_bytes()).unwrap();
        let reparsed = Signature::from_der(der.as_bytes()).unwrap();
        verifying_key.verify(message, &reparsed).unwrap();
    }

    #[test]
    fn malformed_der_is_rejected_with_a_reason() {
        for (name, bytes) in [
            ("empty", vec![]),
            (
                "not a sequence",
                vec![0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            ),
            ("truncated", vec![0x30, 0x06, 0x02, 0x01]),
            (
                "trailing bytes",
                vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00],
            ),
            (
                "wrong inner tag",
                vec![0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x02],
            ),
            ("missing s", vec![0x30, 0x03, 0x02, 0x01, 0x01]),
            (
                "long form length",
                vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02],
            ),
            // 0x02 0x01 0xff would decode as a negative integer.
            (
                "negative integer",
                vec![0x30, 0x06, 0x02, 0x01, 0xff, 0x02, 0x01, 0x02],
            ),
            // Non-minimal: 0x00 0x01 should have been just 0x01.
            (
                "non-minimal integer",
                vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02],
            ),
        ] {
            assert!(der_to_raw(&bytes).is_err(), "should reject {name}");
        }
    }

    #[test]
    fn verification_hashes_the_message_once() {
        // The property the Secure Enclave backend relies on: a signature made over
        // a message must not also verify against that message's digest, or the
        // "hashed twice" bug would be undetectable.
        use sha2::{Digest as _, Sha256};

        let key = SigningKey::random(&mut rand::thread_rng());
        let public_key = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let message = b"AWS4-X509-ECDSA-SHA256\n20260726T011500Z\nscope\ndigest";
        let signature: Signature = key.sign(message);
        let der = signature.to_der().as_bytes().to_vec();

        verify_der_signature(&public_key, message, &der).unwrap();
        assert!(verify_der_signature(&public_key, &Sha256::digest(message), &der).is_err());
    }

    #[test]
    fn verification_rejects_the_wrong_key_a_bad_signature_and_junk_der() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let public_key = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let other = SigningKey::random(&mut rand::thread_rng());
        let other_public_key = other
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let signature: Signature = key.sign(b"message");
        let der = signature.to_der().as_bytes().to_vec();

        assert!(matches!(
            verify_der_signature(&other_public_key, b"message", &der),
            Err(KeystoneError::CertificateKeyMismatch)
        ));
        assert!(verify_der_signature(&public_key, b"other message", &der).is_err());
        assert!(verify_der_signature(&public_key, b"message", b"junk").is_err());
        assert!(verify_der_signature(&[0u8; 65], b"message", &der).is_err());
    }

    #[test]
    fn a_scalar_too_large_for_p256_is_refused() {
        // 33 significant bytes cannot be a P-256 scalar.
        let mut der = vec![0x30, 0x27, 0x02, 0x21];
        der.extend_from_slice(&[0x01; 33]);
        der.extend_from_slice(&[0x02, 0x01, 0x02]);
        assert!(der_to_raw(&der).is_err());
    }
}
