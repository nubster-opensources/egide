//! Authentication error types.

use thiserror::Error;

/// Errors that can occur during authentication.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Invalid credentials (bad token, wrong password, etc.).
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Token has expired.
    #[error("token expired")]
    TokenExpired,

    /// Token not found (no hash stored).
    #[error("token not found")]
    TokenNotFound,

    /// Missing authentication token.
    #[error("missing authentication token")]
    MissingToken,

    /// Permission denied for the requested operation.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid policy configuration.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// Authentication method not enabled.
    #[error("auth method not enabled: {0}")]
    MethodNotEnabled(String),

    /// Backend configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),
}
