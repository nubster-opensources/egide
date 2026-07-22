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

    let nonce_bytes = generate_nonce()?;
    // generate_nonce returns [u8; NONCE_SIZE], so this conversion is infallible
    // and checked at compile time.
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = match associated_data {
        Some(aad) => cipher
            .encrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?,
        None => cipher
            .encrypt(&nonce, plaintext)
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

    // The length check above guarantees the slice holds NONCE_SIZE bytes, but the
    // conversion is fallible on a slice, so the residual case fails closed rather
    // than panicking on a caller supplied buffer.
    let nonce = Nonce::try_from(&ciphertext[..NONCE_SIZE])
        .map_err(|_| CryptoError::InvalidInput("invalid nonce length".to_string()))?;
    let encrypted = &ciphertext[NONCE_SIZE..];

    let plaintext = match associated_data {
        Some(aad) => cipher
            .decrypt(
                &nonce,
                aes_gcm::aead::Payload {
                    msg: encrypted,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed("authentication failed".to_string()))?,
        None => cipher
            .decrypt(&nonce, encrypted)
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
        let key = generate_key().unwrap();
        let plaintext = b"Hello, Egide!";

        let ciphertext = encrypt(&*key, plaintext, None).unwrap();
        let decrypted = decrypt(&*key, &ciphertext, None).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = generate_key().unwrap();
        let plaintext = b"secret data";
        let aad = b"additional authenticated data";

        let ciphertext = encrypt(&*key, plaintext, Some(aad)).unwrap();
        let decrypted = decrypt(&*key, &ciphertext, Some(aad)).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let key = generate_key().unwrap();
        let plaintext = b"secret data";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encrypt(&*key, plaintext, Some(aad)).unwrap();
        let result = decrypt(&*key, &ciphertext, Some(wrong_aad));

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = generate_key().unwrap();
        let key2 = generate_key().unwrap();
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
        let key = generate_key().unwrap();
        let plaintext = b"test";

        let ciphertext = encrypt(&*key, plaintext, None).unwrap();

        assert_eq!(ciphertext.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_key().unwrap();
        let plaintext = b"secret data";

        let mut ciphertext = encrypt(&*key, plaintext, None).unwrap();
        ciphertext[NONCE_SIZE] ^= 0xFF;

        let result = decrypt(&*key, &ciphertext, None);
        assert!(result.is_err());
    }

    fn from_hex(input: &str) -> Vec<u8> {
        assert!(
            input.len().is_multiple_of(2),
            "hex input must have an even length"
        );
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Decrypts a known-answer vector produced outside this codebase.
    ///
    /// The round-trip tests above only prove that `encrypt` and `decrypt` agree
    /// with each other, which stays true even if both drifted away from the
    /// standard together. This vector comes from Project Wycheproof
    /// (`testvectors_v1/aes_gcm_test.json`, tcId 100), an independent test suite
    /// with no relation to the aes-gcm crate, so it pins the implementation to
    /// AES-256-GCM as specified rather than to itself. It is what makes a bump of
    /// the underlying crate observably non-breaking.
    #[test]
    fn test_known_answer_vector_from_external_suite() {
        let key = from_hex("b279f57e19c8f53f2f963f5f2519fdb7c1779be2ca2b3ae8e1128b7d6c627fc4");
        let nonce = from_hex("98bc2c7438d5cd7665d76f6e");
        let associated_data = from_hex("c0");
        let expected_plaintext = from_hex("fcc515b294408c8645c9183e3f4ecee5127846d1");
        let ciphertext_body = from_hex("eb5500e3825952866d911253f8de860c00831c81");
        let tag = from_hex("ecb660e1fb0541ec41e8d68a64141b3a");

        assert_eq!(key.len(), KEY_SIZE);
        assert_eq!(nonce.len(), NONCE_SIZE);
        assert_eq!(tag.len(), TAG_SIZE);

        // decrypt expects the wire format nonce || ciphertext || tag.
        let mut wire = nonce;
        wire.extend_from_slice(&ciphertext_body);
        wire.extend_from_slice(&tag);

        let plaintext = decrypt(&key, &wire, Some(&associated_data)).unwrap();

        assert_eq!(&*plaintext, &expected_plaintext[..]);
    }
}
