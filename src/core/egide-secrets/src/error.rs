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

    /// Invalid secret path.
    #[error("invalid secret path: {0}")]
    InvalidPath(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] egide_crypto::CryptoError),
}
