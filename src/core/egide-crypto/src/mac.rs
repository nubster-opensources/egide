//! Keyed message authentication and canonical field encoding.
//!
//! Provides an injective length-prefixed encoding for ordered byte fields and
//! a keyed HMAC-SHA256 tag over those bytes, with constant-time verification.
//! Used to authenticate mutable storage rows (the secrets version pointer and
//! the transit key policy row) and to build tamper-proof AEAD associated data.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::CryptoError;

type HmacSha256 = Hmac<Sha256>;

/// Size of an HMAC-SHA256 tag in bytes.
pub const MAC_SIZE: usize = 32;

/// Encodes an ordered list of byte fields into an unambiguous byte string.
///
/// Each field is prefixed by its length as a u32 big-endian integer, making the
/// encoding injective: two distinct field lists can never produce equal bytes.
/// This prevents field-splitting (canonicalization) attacks that a delimiter
/// based scheme would allow.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if any field is longer than `u32::MAX`
/// bytes and therefore cannot be length-prefixed.
pub fn encode_fields(fields: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::new();
    for field in fields {
        let length = u32::try_from(field.len()).map_err(|_| {
            CryptoError::InvalidInput("field too long for u32 length prefix".to_string())
        })?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

/// Computes an HMAC-SHA256 tag over `data` under `key`.
///
/// # Errors
///
/// Returns [`CryptoError::SignatureFailed`] if the MAC state cannot be
/// constructed from the key (not reachable for HMAC, which accepts any key
/// length, but surfaced rather than panicked on).
pub fn compute_mac(key: &[u8], data: &[u8]) -> Result<[u8; MAC_SIZE], CryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|e| CryptoError::SignatureFailed(e.to_string()))?;
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Verifies `tag` against a freshly computed HMAC-SHA256 of `data` under `key`.
///
/// The comparison is constant-time. A tag of the wrong length compares unequal
/// without leaking the mismatch position.
///
/// # Errors
///
/// Propagates any error from [`compute_mac`].
pub fn verify_mac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool, CryptoError> {
    let computed = compute_mac(key, data)?;
    Ok(computed[..].ct_eq(tag).into())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn encode_fields_is_length_prefixed() {
        let encoded = encode_fields(&[b"ab", b"c"]).unwrap();
        // 00 00 00 02 'a' 'b' 00 00 00 01 'c'
        assert_eq!(encoded, vec![0, 0, 0, 2, b'a', b'b', 0, 0, 0, 1, b'c']);
    }

    #[test]
    fn encode_fields_is_injective_across_split_points() {
        // Without length prefixes, ("a", "bc") and ("ab", "c") would both be
        // "abc" under a naive concatenation, and ("a:b", "c") vs ("a", "b:c")
        // would collide under a ':' delimiter. Length prefixing separates them.
        let a = encode_fields(&[b"a", b"bc"]).unwrap();
        let b = encode_fields(&[b"ab", b"c"]).unwrap();
        assert_ne!(a, b);

        let c = encode_fields(&[b"a:b", b"c"]).unwrap();
        let d = encode_fields(&[b"a", b"b:c"]).unwrap();
        assert_ne!(c, d);
    }

    #[test]
    fn encode_fields_empty_field_is_distinct_from_absent_field() {
        let one_empty = encode_fields(&[b""]).unwrap();
        let two_empty = encode_fields(&[b"", b""]).unwrap();
        assert_ne!(one_empty, two_empty);
        assert_eq!(one_empty, vec![0, 0, 0, 0]);
    }

    #[test]
    fn compute_mac_matches_rfc4231_test_case_2() {
        // RFC 4231, Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let tag = compute_mac(key, data).unwrap();
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(tag.as_slice(), expected.as_slice());
    }

    #[test]
    fn verify_mac_accepts_valid_tag() {
        let key = b"secret subkey material";
        let data = encode_fields(&[b"transit", b"policy", b"v1"]).unwrap();
        let tag = compute_mac(key, &data).unwrap();
        assert!(verify_mac(key, &data, &tag).unwrap());
    }

    #[test]
    fn verify_mac_rejects_flipped_bit() {
        let key = b"secret subkey material";
        let data = encode_fields(&[b"transit", b"policy", b"v1"]).unwrap();
        let mut tag = compute_mac(key, &data).unwrap();
        tag[0] ^= 0x01;
        assert!(!verify_mac(key, &data, &tag).unwrap());
    }

    #[test]
    fn verify_mac_rejects_wrong_length_tag() {
        let key = b"secret subkey material";
        let data = encode_fields(&[b"x"]).unwrap();
        let short = [0u8; 8];
        assert!(!verify_mac(key, &data, &short).unwrap());
    }

    #[test]
    fn verify_mac_rejects_wrong_key() {
        let data = encode_fields(&[b"pointer"]).unwrap();
        let tag = compute_mac(b"key one", &data).unwrap();
        assert!(!verify_mac(b"key two", &data, &tag).unwrap());
    }
}
