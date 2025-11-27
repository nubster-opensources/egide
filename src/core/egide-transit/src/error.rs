//! Transit engine error types.

use thiserror::Error;

/// Errors that can occur in the Transit Engine.
#[derive(Debug, Error)]
pub enum TransitError {
    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Invalid ciphertext format.
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Key is not enabled for this operation.
    #[error("operation not allowed: {0}")]
    OperationNotAllowed(String),

    /// KMS error.
    #[error("kms error: {0}")]
    Kms(#[from] egide_kms::KmsError),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] egide_crypto::CryptoError),
}
