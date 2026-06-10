//! Transit engine error types.

use thiserror::Error;

/// Errors that can occur in the Transit Engine.
#[derive(Debug, Error)]
pub enum TransitError {
    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Key already exists.
    #[error("key already exists: {0}")]
    KeyExists(String),

    /// Key version not found.
    #[error("key version not found: {name} v{version}")]
    VersionNotFound {
        /// Key name.
        name: String,
        /// Version number.
        version: u32,
    },

    /// Version too old for encryption.
    #[error("key version {version} is below min_encryption_version {min}")]
    VersionBelowMinEncryption {
        /// Requested version.
        version: u32,
        /// Minimum allowed version.
        min: u32,
    },

    /// Version too old for decryption.
    #[error("key version {version} is below min_decryption_version {min}")]
    VersionBelowMinDecryption {
        /// Ciphertext version.
        version: u32,
        /// Minimum allowed version.
        min: u32,
    },

    /// Invalid ciphertext format.
    #[error("invalid ciphertext format")]
    InvalidCiphertext,

    /// Decryption failed.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Operation not allowed on this key.
    #[error("operation not allowed: {0}")]
    OperationNotAllowed(String),

    /// Invalid key name.
    #[error("invalid key name: {0}")]
    InvalidKeyName(String),

    /// Invalid key type.
    #[error("invalid key type: {0}")]
    InvalidKeyType(String),

    /// Key is not exportable.
    #[error("key is not exportable: {0}")]
    NotExportable(String),

    /// Key deletion not allowed.
    #[error("deletion not allowed for key: {0}")]
    DeletionNotAllowed(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<egide_crypto::CryptoError> for TransitError {
    fn from(e: egide_crypto::CryptoError) -> Self {
        TransitError::Crypto(e.to_string())
    }
}

impl From<egide_storage::StorageError> for TransitError {
    fn from(e: egide_storage::StorageError) -> Self {
        TransitError::Storage(e.to_string())
    }
}
