//! Keyed message authentication and canonical field encoding.
//!
//! Provides an injective length-prefixed encoding for ordered byte fields and
//! a keyed HMAC-SHA256 tag over those bytes, with constant-time verification.
//! Used to authenticate mutable storage rows (the secrets version pointer and
//! the transit key policy row) and to build tamper-proof AEAD associated data.

use crate::error::CryptoError;

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
}
