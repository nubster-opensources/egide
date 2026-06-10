//! PKI engine error types.

use thiserror::Error;

/// Errors that can occur in the PKI Engine.
#[derive(Debug, Error)]
pub enum PkiError {
    /// Certificate Authority not initialized.
    #[error("CA not initialized")]
    CaNotInitialized,

    /// Certificate not found.
    #[error("certificate not found: {0}")]
    CertificateNotFound(String),

    /// Certificate has been revoked.
    #[error("certificate revoked: {0}")]
    CertificateRevoked(String),

    /// Certificate has expired.
    #[error("certificate expired: {0}")]
    CertificateExpired(String),

    /// Invalid certificate request.
    #[error("invalid certificate request: {0}")]
    InvalidRequest(String),

    /// Template not found.
    #[error("template not found: {0}")]
    TemplateNotFound(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(#[from] egide_crypto::CryptoError),
}
