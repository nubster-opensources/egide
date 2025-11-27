//! Storage error types.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Entry not found.
    #[error("entry not found: {0}")]
    NotFound(String),

    /// Entry already exists.
    #[error("entry already exists: {0}")]
    AlreadyExists(String),

    /// Connection error.
    #[error("connection error: {0}")]
    Connection(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Transaction error.
    #[error("transaction error: {0}")]
    Transaction(String),

    /// Generic I/O error.
    #[error("io error: {0}")]
    Io(String),
}
