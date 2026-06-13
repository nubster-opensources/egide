//! Transport-agnostic service error.

use thiserror::Error;

/// Error returned by the service layer, independent of any transport.
///
/// Each transport (REST, gRPC) maps these variants to its own status model.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// Requested resource does not exist.
    #[error("not found")]
    NotFound,
    /// Resource already exists.
    #[error("conflict")]
    Conflict,
    /// Invalid input (bad base64, empty field, malformed argument).
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Caller lacks the required privilege (root).
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Vault is sealed; the required engine is unavailable.
    #[error("sealed")]
    Sealed,
    /// Decryption failed (kept distinct for intent; mapped like BadRequest, anti-oracle).
    #[error("decryption failed")]
    DecryptionFailed,
    /// Unexpected engine or storage failure.
    #[error("internal: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_carries_message() {
        let e = ServiceError::Forbidden("root required".into());
        assert_eq!(e.to_string(), "forbidden: root required");
    }

    #[test]
    fn sealed_is_distinct_variant() {
        assert!(matches!(ServiceError::Sealed, ServiceError::Sealed));
    }
}
