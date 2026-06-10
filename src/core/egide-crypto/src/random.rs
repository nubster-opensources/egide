//! Cryptographically secure random generation.
//!
//! Uses the operating system's CSPRNG for all random number generation.

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::aead::{KEY_SIZE, NONCE_SIZE};

/// Generates a cryptographically secure random 256-bit key.
///
/// The key is wrapped in `Zeroizing` to ensure it is cleared from memory when dropped.
pub fn generate_key() -> Zeroizing<[u8; KEY_SIZE]> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    OsRng.fill_bytes(&mut *key);
    key
}

/// Generates a cryptographically secure random nonce for AES-GCM.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generates cryptographically secure random bytes.
///
/// # Arguments
///
/// * `len` - Number of random bytes to generate
pub fn generate_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generates a cryptographically secure random token as a hex string.
///
/// # Arguments
///
/// * `byte_len` - Number of random bytes (output string will be 2x this length)
pub fn generate_token(byte_len: usize) -> String {
    let bytes = generate_bytes(byte_len);
    hex_encode(&bytes)
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
        let key = generate_key();
        assert_eq!(key.len(), KEY_SIZE);
    }

    #[test]
    fn test_generate_key_unique() {
        let key1 = generate_key();
        let key2 = generate_key();
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_generate_nonce_length() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), NONCE_SIZE);
    }

    #[test]
    fn test_generate_bytes_length() {
        for len in [0, 1, 16, 32, 64, 128] {
            let bytes = generate_bytes(len);
            assert_eq!(bytes.len(), len);
        }
    }

    #[test]
    fn test_generate_token_length() {
        let token = generate_token(16);
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn test_generate_token_hex_format() {
        let token = generate_token(16);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_randomness_distribution() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let token = generate_token(8);
            assert!(seen.insert(token), "duplicate token generated");
        }
    }
}
