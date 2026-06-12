//! Native service tokens: opaque `egst_<id>.<secret>` credentials issued by Egide.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public prefix of an Egide service token.
pub const SERVICE_TOKEN_PREFIX: &str = "egst_";

/// Storage key prefix under which service token records are persisted.
pub const SERVICE_TOKEN_STORAGE_PREFIX: &str = "service-tokens/";

/// Persisted record for a service token. Only the secret hash is stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceTokenRecord {
    /// Public token identifier (lookup key).
    pub token_id: String,
    /// Hex-encoded SHA-256 hash of the token secret.
    pub secret_hash: String,
    /// Name of the service the token belongs to.
    pub service_name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Revocation timestamp (Unix seconds), if revoked.
    pub revoked_at: Option<u64>,
}

/// Parses an opaque service token of the form `egst_<token_id>.<secret>`.
///
/// Returns `None` if the prefix is missing, the separator is absent, or either
/// part is empty.
pub fn parse_token(token: &str) -> Option<(String, String)> {
    let rest = token.strip_prefix(SERVICE_TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('.')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id.to_string(), secret.to_string()))
}

/// Formats a service token from its identifier and secret.
pub fn format_token(token_id: &str, secret: &str) -> String {
    format!("{SERVICE_TOKEN_PREFIX}{token_id}.{secret}")
}

/// Computes the hex-encoded SHA-256 hash of a token secret.
pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_token() {
        let parsed = parse_token("egst_abc123.deadbeef");
        assert_eq!(parsed, Some(("abc123".to_string(), "deadbeef".to_string())));
    }

    #[test]
    fn rejects_token_without_prefix() {
        assert_eq!(parse_token("abc123.deadbeef"), None);
    }

    #[test]
    fn rejects_token_without_separator() {
        assert_eq!(parse_token("egst_abc123deadbeef"), None);
    }

    #[test]
    fn rejects_token_with_empty_parts() {
        assert_eq!(parse_token("egst_.deadbeef"), None);
        assert_eq!(parse_token("egst_abc123."), None);
    }

    #[test]
    fn formats_a_token() {
        assert_eq!(format_token("abc", "sec"), "egst_abc.sec");
    }

    #[test]
    fn hash_is_stable_and_hex() {
        let h = hash_secret("hello");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_secret("hello"));
        assert_ne!(h, hash_secret("world"));
    }
}
