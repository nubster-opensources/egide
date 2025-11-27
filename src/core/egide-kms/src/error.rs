//! KMS engine error types.

use thiserror::Error;

/// Errors that can occur in the KMS Engine.
#[derive(Debug, Error)]
pub enum KmsError {
    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Key version not found.
    #[error("key version not found: {name} v{version}")]
    VersionNotFound {
        /// Key name.
        name: String,
        /// Version number.
        version: u32,
    },

    /// Unsupported key type.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),

    /// Operation not allowed for key type.
    #[error("operation not allowed: {operation} on {key_type}")]
    OperationNotAllowed {
        /// Operation name.
        operation: String,
        /// Key type.
        key_type: String,
    },

    /// Key is disabled.
    #[error("key is disabled: {0}")]
    KeyDisabled(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] egide_crypto::CryptoError),
}
