//! Secrets engine error types.

use thiserror::Error;

/// Errors that can occur in the Secrets Engine.
#[derive(Debug, Error)]
pub enum SecretsError {
    /// Secret not found.
    #[error("secret not found: {0}")]
    NotFound(String),

    /// Secret version not found.
    #[error("secret version not found: {path} v{version}")]
    VersionNotFound {
        /// Secret path.
        path: String,
        /// Version number.
        version: u32,
    },

    /// Secret has expired.
    #[error("secret has expired: {0}")]
    Expired(String),

    /// Secret is deleted.
    #[error("secret is deleted: {0}")]
    Deleted(String),

    /// Secret is not deleted (cannot undelete).
    #[error("secret is not deleted: {0}")]
    NotDeleted(String),

    /// CAS (check-and-set) version mismatch.
    #[error("version mismatch: expected {expected}, found {found}")]
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Actual version.
        found: u32,
    },

    /// Invalid secret path.
    #[error("invalid secret path: {0}")]
    InvalidPath(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<egide_crypto::CryptoError> for SecretsError {
    fn from(e: egide_crypto::CryptoError) -> Self {
        SecretsError::Crypto(e.to_string())
    }
}

impl From<egide_storage::StorageError> for SecretsError {
    fn from(e: egide_storage::StorageError) -> Self {
        SecretsError::Storage(e.to_string())
    }
}
