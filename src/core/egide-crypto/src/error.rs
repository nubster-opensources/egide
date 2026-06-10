//! Cryptographic error types.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Signature creation failed.
    #[error("signature creation failed: {0}")]
    SignatureFailed(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    VerificationFailed,

    /// Invalid key format or size.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Invalid input data.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
