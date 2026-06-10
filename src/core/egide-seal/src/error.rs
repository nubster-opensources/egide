//! Seal error types.

use thiserror::Error;

/// Errors that can occur during seal operations.
#[derive(Debug, Error)]
pub enum SealError {
    /// Vault is already initialized.
    #[error("vault already initialized")]
    AlreadyInitialized,

    /// Vault is not initialized.
    #[error("vault not initialized")]
    NotInitialized,

    /// Vault is sealed.
    #[error("vault is sealed")]
    Sealed,

    /// Vault is already unsealed.
    #[error("vault already unsealed")]
    AlreadyUnsealed,

    /// Invalid Shamir configuration.
    #[error("invalid shamir config: {0}")]
    InvalidConfig(String),

    /// Invalid share.
    #[error("invalid share: {0}")]
    InvalidShare(String),

    /// Duplicate share submitted.
    #[error("duplicate share (index {0})")]
    DuplicateShare(u8),

    /// Failed to reconstruct master key.
    #[error("failed to reconstruct master key")]
    ReconstructionFailed,

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Crypto error.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<egide_storage::StorageError> for SealError {
    fn from(e: egide_storage::StorageError) -> Self {
        SealError::Storage(e.to_string())
    }
}
