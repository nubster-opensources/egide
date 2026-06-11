//! AES-256-GCM authenticated encryption.
//!
//! Provides authenticated encryption with associated data (AEAD) using AES-256-GCM.
//! This is the primary encryption algorithm used throughout Egide for encrypting secrets.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::random::generate_nonce;

/// Size of an AES-256 key in bytes.
pub const KEY_SIZE: usize = 32;

/// Size of a GCM nonce in bytes.
pub const NONCE_SIZE: usize = 12;

/// Size of a GCM authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Encrypts plaintext using AES-256-GCM.
///
/// The nonce is automatically generated and prepended to the ciphertext.
/// Format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `associated_data` - Optional additional data to authenticate (not encrypted)
///
/// # Returns
///
/// Ciphertext with prepended nonce and appended authentication tag.
pub fn encrypt(
    key: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKey(format!(
            "expected {} bytes, got {}",
            KEY_SIZE,
            key.len()
        )));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = match associated_data {
        Some(aad) => cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?,
        None => cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?,
    };

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypts ciphertext using AES-256-GCM.
///
/// Expects the nonce to be prepended to the ciphertext (as produced by `encrypt`).
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `ciphertext` - Data to decrypt (nonce || ciphertext || tag)
/// * `associated_data` - Optional additional data that was authenticated
///
/// # Returns
///
/// Decrypted plaintext wrapped in `Zeroizing` for automatic memory cleanup.
pub fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKey(format!(
            "expected {} bytes, got {}",
            KEY_SIZE,
            key.len()
        )));
    }

    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(CryptoError::InvalidInput(
            "ciphertext too short".to_string(),
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let encrypted = &ciphertext[NONCE_SIZE..];

    let plaintext = match associated_data {
        Some(aad) => cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: encrypted,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed("authentication failed".to_string()))?,
        None => cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| CryptoError::DecryptionFailed("authentication failed".to_string()))?,
    };

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::random::generate_key;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"Hello, Egide!";

        let ciphertext = encrypt(&*key, plaintext, None).unwrap();
        let decrypted = decrypt(&*key, &ciphertext, None).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = generate_key();
        let plaintext = b"secret data";
        let aad = b"additional authenticated data";

        let ciphertext = encrypt(&*key, plaintext, Some(aad)).unwrap();
        let decrypted = decrypt(&*key, &ciphertext, Some(aad)).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = generate_key();
        let plaintext = b"secret data";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encrypt(&*key, plaintext, Some(aad)).unwrap();
        let result = decrypt(&*key, &ciphertext, Some(wrong_aad));

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"secret data";

        let ciphertext = encrypt(&*key1, plaintext, None).unwrap();
        let result = decrypt(&*key2, &ciphertext, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = vec![0u8; 16];
        let plaintext = b"test";

        let result = encrypt(&short_key, plaintext, None);
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_ciphertext_format() {
        let key = generate_key();
        let plaintext = b"test";

        let ciphertext = encrypt(&*key, plaintext, None).unwrap();

        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_key();
        let plaintext = b"secret data";

        let mut ciphertext = encrypt(&*key, plaintext, None).unwrap();
        ciphertext[NONCE_SIZE] ^= 0xFF;

        let result = decrypt(&*key, &ciphertext, None);
        assert!(result.is_err());
    }
}
