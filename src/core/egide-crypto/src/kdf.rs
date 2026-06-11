//! Key derivation functions.
//!
//! Provides HKDF (HMAC-based Key Derivation Function) as specified in RFC 5869.
//! Used to derive encryption keys from master secrets.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::KEY_SIZE;
use crate::error::CryptoError;

/// Derives a key using HKDF-SHA256.
///
/// HKDF is a two-step process:
/// 1. Extract: Creates a pseudorandom key from the input key material
/// 2. Expand: Generates output key material of desired length
///
/// # Arguments
///
/// * `ikm` - Input key material (the secret to derive from)
/// * `salt` - Optional salt value (recommended for security)
/// * `info` - Context and application-specific information
/// * `length` - Desired output key length in bytes
///
/// # Returns
///
/// Derived key wrapped in `Zeroizing` for automatic memory cleanup.
pub fn derive_key(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if length == 0 {
        return Err(CryptoError::InvalidInput(
            "output length must be > 0".to_string(),
        ));
    }

    if length > 255 * 32 {
        return Err(CryptoError::InvalidInput(
            "output length too large for HKDF-SHA256".to_string(),
        ));
    }

    let hkdf = Hkdf::<Sha256>::new(salt, ikm);

    let mut okm = Zeroizing::new(vec![0u8; length]);
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyGenerationFailed("HKDF expansion failed".to_string()))?;

    Ok(okm)
}

/// Derives an AES-256 encryption key using HKDF-SHA256.
///
/// Convenience wrapper around `derive_key` that returns exactly 32 bytes.
///
/// # Arguments
///
/// * `master_key` - The master key to derive from
/// * `context` - Unique context string for this key derivation
pub fn derive_encryption_key(
    master_key: &[u8],
    context: &[u8],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let derived = derive_key(master_key, None, context, KEY_SIZE)?;

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&derived);

    Ok(key)
}

/// Derives multiple keys from a single master key.
///
/// Useful for deriving separate keys for different purposes
/// (e.g., encryption key and authentication key).
///
/// # Arguments
///
/// * `master_key` - The master key to derive from
/// * `contexts` - List of context strings, one per key to derive
///
/// # Returns
///
/// Vector of derived keys, one per context.
pub fn derive_multiple_keys(
    master_key: &[u8],
    contexts: &[&[u8]],
) -> Result<Vec<Zeroizing<[u8; KEY_SIZE]>>, CryptoError> {
    contexts
        .iter()
        .map(|ctx| derive_encryption_key(master_key, ctx))
        .collect()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_basic() {
        let ikm = b"input key material";
        let info = b"context";

        let key = derive_key(ikm, None, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_with_salt() {
        let ikm = b"input key material";
        let salt = b"random salt";
        let info = b"context";

        let key = derive_key(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let ikm = b"input key material";
        let info = b"context";

        let key1 = derive_key(ikm, None, info, 32).unwrap();
        let key2 = derive_key(ikm, None, info, 32).unwrap();

        assert_eq!(*key1, *key2);
    }

    #[test]
    fn test_derive_key_different_info_different_keys() {
        let ikm = b"input key material";

        let key1 = derive_key(ikm, None, b"context1", 32).unwrap();
        let key2 = derive_key(ikm, None, b"context2", 32).unwrap();

        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_derive_key_different_salt_different_keys() {
        let ikm = b"input key material";
        let info = b"context";

        let key1 = derive_key(ikm, Some(b"salt1"), info, 32).unwrap();
        let key2 = derive_key(ikm, Some(b"salt2"), info, 32).unwrap();

        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_derive_encryption_key() {
        let master = b"master secret";
        let context = b"encryption";

        let key = derive_encryption_key(master, context).unwrap();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_derive_multiple_keys() {
        let master = b"master secret";
        let contexts: &[&[u8]] = &[b"key1", b"key2", b"key3"];

        let keys = derive_multiple_keys(master, contexts).unwrap();

        assert_eq!(keys.len(), 3);
        assert_ne!(*keys[0], *keys[1]);
        assert_ne!(*keys[1], *keys[2]);
    }

    #[test]
    fn test_derive_key_zero_length_fails() {
        let ikm = b"input";
        let result = derive_key(ikm, None, b"info", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key_variable_lengths() {
        let ikm = b"input key material";
        let info = b"context";

        for len in [16, 32, 48, 64, 128] {
            let key = derive_key(ikm, None, info, len).unwrap();
            assert_eq!(key.len(), len);
        }
    }

    #[test]
    fn test_hkdf_rfc5869_test_vector() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let okm = derive_key(&ikm, Some(&salt), &info, 42).unwrap();

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        assert_eq!(&*okm, &expected);
    }
}
