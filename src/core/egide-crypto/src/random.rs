//! Cryptographically secure random generation.
//!
//! Uses the operating system's CSPRNG for all random number generation.

use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::Zeroizing;

use crate::aead::{KEY_SIZE, NONCE_SIZE};
use crate::error::CryptoError;

/// Fills `dest` with bytes from the operating system's CSPRNG.
fn fill_random(dest: &mut [u8]) -> Result<(), CryptoError> {
    SysRng
        .try_fill_bytes(dest)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))
}

/// Generates a cryptographically secure random 256-bit key.
///
/// The key is wrapped in `Zeroizing` to ensure it is cleared from memory when dropped.
///
/// # Errors
///
/// Returns a [`CryptoError::RandomGenerationFailed`] if the operating system's
/// CSPRNG fails to produce output.
pub fn generate_key() -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    fill_random(&mut *key)?;
    Ok(key)
}

/// Generates a cryptographically secure random nonce for AES-GCM.
///
/// # Errors
///
/// Returns a [`CryptoError::RandomGenerationFailed`] if the operating system's
/// CSPRNG fails to produce output.
pub fn generate_nonce() -> Result<[u8; NONCE_SIZE], CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Generates cryptographically secure random bytes.
///
/// # Arguments
///
/// * `len` - Number of random bytes to generate
///
/// # Errors
///
/// Returns a [`CryptoError::RandomGenerationFailed`] if the operating system's
/// CSPRNG fails to produce output.
pub fn generate_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

/// Generates a cryptographically secure random token as a hex string.
///
/// # Arguments
///
/// * `byte_len` - Number of random bytes (output string will be 2x this length)
///
/// # Errors
///
/// Returns a [`CryptoError::RandomGenerationFailed`] if the operating system's
/// CSPRNG fails to produce output.
pub fn generate_token(byte_len: usize) -> Result<String, CryptoError> {
    let bytes = generate_bytes(byte_len)?;
    Ok(hex_encode(&bytes))
}

/// Encodes bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0F) as usize] as char);
    }
    hex
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_key_length() {
        let key = generate_key().unwrap();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_generate_key_unique() {
        let key1 = generate_key().unwrap();
        let key2 = generate_key().unwrap();
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce().unwrap();
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_generate_bytes_length() {
        for len in [0, 1, 16, 32, 64, 128] {
            let bytes = generate_bytes(len).unwrap();
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn test_generate_token_length() {
        let token = generate_token(16).unwrap();
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn test_generate_token_hex_format() {
        let token = generate_token(16).unwrap();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_randomness_distribution() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let token = generate_token(8).unwrap();
            assert!(seen.insert(token), "duplicate token generated");
        }
    }
}
