//! Root token authentication backend.
//!
//! Validates root tokens for dev mode and legacy compatibility.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{AuthBackend, AuthContext, AuthError};

/// Callback for retrieving the stored root token hash.
///
/// This allows the backend to be decoupled from the storage implementation.
pub type RootTokenHashFn = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Authentication backend for root tokens.
///
/// This backend validates tokens against a stored Argon2id hash.
/// Used for dev mode and legacy single-token authentication.
pub struct RootTokenBackend {
    /// Function to get the current root token hash.
    get_hash: RootTokenHashFn,
    /// Cached hash for performance (updated on each validation).
    cached_hash: RwLock<Option<String>>,
}

impl RootTokenBackend {
    /// Creates a new root token backend.
    ///
    /// # Arguments
    ///
    /// * `get_hash` - Callback that returns the stored Argon2id hash of the root token.
    pub fn new(get_hash: RootTokenHashFn) -> Self {
        Self {
            get_hash,
            cached_hash: RwLock::new(None),
        }
    }

    /// Creates a backend with a static hash (for testing).
    pub fn with_static_hash(hash: String) -> Self {
        let hash_clone = hash.clone();
        Self::new(Arc::new(move || Some(hash_clone.clone())))
    }
}

#[async_trait]
impl AuthBackend for RootTokenBackend {
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Get the stored hash
        let hash = (self.get_hash)().ok_or(AuthError::TokenNotFound)?;

        // Update cache
        {
            let mut cache = self.cached_hash.write().await;
            *cache = Some(hash.clone());
        }

        // Parse the hash
        let parsed_hash =
            PasswordHash::new(&hash).map_err(|_| AuthError::Storage("invalid hash".into()))?;

        // Verify with Argon2id
        let valid = Argon2::default()
            .verify_password(token.as_bytes(), &parsed_hash)
            .is_ok();

        if !valid {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(AuthContext::root())
    }

    fn name(&self) -> &'static str {
        "root-token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    use rand::rngs::OsRng;

    fn hash_token(token: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(token.as_bytes(), &salt)
            .expect("failed to hash password")
            .to_string()
    }

    #[tokio::test]
    async fn test_valid_root_token() {
        let token = "my-secret-root-token";
        let hash = hash_token(token);

        let backend = RootTokenBackend::with_static_hash(hash);
        let ctx = backend.validate(token).await.expect("validation failed");

        assert_eq!(ctx.account_id, "root");
        assert!(ctx.is_root());
    }

    #[tokio::test]
    async fn test_invalid_root_token() {
        let token = "my-secret-root-token";
        let hash = hash_token(token);

        let backend = RootTokenBackend::with_static_hash(hash);
        let result = backend.validate("wrong-token").await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_no_hash_stored() {
        let backend = RootTokenBackend::new(Arc::new(|| None));
        let result = backend.validate("any-token").await;

        assert!(matches!(result, Err(AuthError::TokenNotFound)));
    }
}
