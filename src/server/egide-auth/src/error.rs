//! Authentication error types.

use thiserror::Error;

/// Errors that can occur during authentication.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid credentials.
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Token expired.
    #[error("token expired")]
    TokenExpired,

    /// Token not found.
    #[error("token not found")]
    TokenNotFound,

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid policy.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// Authentication method not enabled.
    #[error("auth method not enabled: {0}")]
    MethodNotEnabled(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),
}
