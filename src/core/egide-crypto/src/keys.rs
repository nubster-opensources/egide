//! Secure key types with automatic memory zeroization.
//!
//! All key types implement `Zeroize` and `ZeroizeOnDrop` to ensure
//! sensitive key material is securely erased from memory when no longer needed.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::KEY_SIZE;
use crate::error::CryptoError;
use crate::random::generate_key;

/// A 256-bit symmetric encryption key with automatic zeroization.
///
/// This type wraps a raw key and ensures it is securely erased
/// from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    bytes: [u8; KEY_SIZE],
}

impl SymmetricKey {
    /// Generates a new random symmetric key.
    pub fn generate() -> Self {
        let key = generate_key();
        Self { bytes: *key }
    }

    /// Creates a symmetric key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "expected {} bytes, got {}",
                KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: key_bytes })
    }

    /// Returns the raw key bytes.
    ///
    /// Use with caution - the returned slice is not zeroized automatically.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// A master key used for deriving other keys.
///
/// Master keys are typically generated during vault initialization
/// and protected by Shamir's Secret Sharing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    bytes: [u8; KEY_SIZE],
}

impl MasterKey {
    /// Generates a new random master key.
    pub fn generate() -> Self {
        let key = generate_key();
        Self { bytes: *key }
    }

    /// Creates a master key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKey(format!(
                "expected {} bytes, got {}",
                KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; KEY_SIZE];
        key_bytes.copy_from_slice(bytes);

        Ok(Self { bytes: key_bytes })
    }

    /// Returns the raw key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_key_generate() {
        let key = SymmetricKey::generate();
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }

    #[test]
    fn test_symmetric_key_from_bytes() {
        let bytes = [0x42u8; KEY_SIZE];
        let key = SymmetricKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_symmetric_key_invalid_length() {
        let bytes = [0u8; 16];
        let result = SymmetricKey::from_bytes(&bytes);
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_symmetric_key_debug_redacted() {
        let key = SymmetricKey::generate();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("42"));
    }

    #[test]
    fn test_master_key_generate() {
        let key = MasterKey::generate();
        assert_eq!(key.as_bytes().len(), KEY_SIZE);
    }

    #[test]
    fn test_master_key_from_bytes() {
        let bytes = [0x42u8; KEY_SIZE];
        let key = MasterKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_master_key_debug_redacted() {
        let key = MasterKey::generate();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_keys_are_unique() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }
}
