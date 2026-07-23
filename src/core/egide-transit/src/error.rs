//! Transit engine error types.

use thiserror::Error;

/// Errors that can occur in the Transit Engine.
///
/// Marked `#[non_exhaustive]`: this crate is published, and a future patch
/// may need to add a variant (for example a new security-relevant failure
/// mode) without forcing a major version bump on every downstream consumer
/// that matches on this enum.
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// Key type accepted by the API but not implemented by this build.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(crate::KeyType),

    /// A persisted key declares an algorithm this build does not implement.
    ///
    /// Unlike [`TransitError::UnsupportedKeyType`], which rejects a type the
    /// caller is requesting right now, this variant means the request itself
    /// is well-formed: the problem is server-side state, a key row written
    /// under a type this build never actually implemented (for example
    /// `chacha20-poly1305` on a key created by an earlier release). Retrying
    /// the same request cannot succeed; the key must be rotated onto an
    /// implemented algorithm or replaced.
    #[error("key algorithm not implemented: the persisted key declares {0}, which this build does not implement")]
    KeyAlgorithmNotImplemented(crate::KeyType),

    /// Ciphertext declares an algorithm the engine does not implement.
    #[error("ciphertext algorithm {found} does not match engine algorithm {expected}")]
    CiphertextAlgorithmMismatch {
        /// Algorithm the engine actually implements.
        expected: crate::KeyType,
        /// Algorithm declared by the ciphertext.
        found: crate::KeyType,
    },

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

    /// Authenticated policy data failed an integrity check (tampered or unparsable).
    #[error("integrity check failed: {0}")]
    Integrity(String),

    /// The system clock is set before the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    Clock,
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
