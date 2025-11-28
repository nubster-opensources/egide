//! Root token authentication backend.
//!
//! Validates root tokens for dev mode and legacy compatibility.

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use egide_storage::StorageBackend;
use std::sync::Arc;

use crate::{AuthBackend, AuthContext, AuthError};

/// The storage key for the root token hash.
pub const ROOT_TOKEN_HASH_KEY: &str = "root_token_hash";

/// Authentication backend for root tokens.
///
/// This backend validates tokens against a stored Argon2id hash.
/// Used for dev mode and legacy single-token authentication.
pub struct RootTokenBackend<S: StorageBackend> {
    /// Storage backend for reading the root token hash.
    storage: Arc<S>,
}

impl<S: StorageBackend> RootTokenBackend<S> {
    /// Creates a new root token backend.
    ///
    /// # Arguments
    ///
    /// * `storage` - Storage backend to read the root token hash from.
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<S: StorageBackend + 'static> AuthBackend for RootTokenBackend<S> {
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Get the stored hash from storage (async!)
        let hash_bytes = self
            .storage
            .get(ROOT_TOKEN_HASH_KEY)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?
            .ok_or(AuthError::TokenNotFound)?;

        let hash =
            String::from_utf8(hash_bytes).map_err(|_| AuthError::Storage("invalid hash".into()))?;

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
    use egide_storage::StorageError;
    use rand::rngs::OsRng;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    fn hash_token(token: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(token.as_bytes(), &salt)
            .expect("failed to hash password")
            .to_string()
    }

    /// In-memory storage for testing.
    struct MemoryStorage {
        data: RwLock<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: RwLock::new(HashMap::new()),
            }
        }

        async fn set(&self, key: &str, value: Vec<u8>) {
            self.data.write().await.insert(key.to_string(), value);
        }
    }

    #[async_trait]
    impl StorageBackend for MemoryStorage {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.data.read().await.get(key).cloned())
        }

        async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
            self.data
                .write()
                .await
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.data.write().await.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
            Ok(self
                .data
                .read()
                .await
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    #[tokio::test]
    async fn test_valid_root_token() {
        let token = "my-secret-root-token";
        let hash = hash_token(token);

        let storage = Arc::new(MemoryStorage::new());
        storage.set(ROOT_TOKEN_HASH_KEY, hash.into_bytes()).await;

        let backend = RootTokenBackend::new(storage);
        let ctx = backend.validate(token).await.expect("validation failed");

        assert_eq!(ctx.account_id, "root");
        assert!(ctx.is_root());
    }

    #[tokio::test]
    async fn test_invalid_root_token() {
        let token = "my-secret-root-token";
        let hash = hash_token(token);

        let storage = Arc::new(MemoryStorage::new());
        storage.set(ROOT_TOKEN_HASH_KEY, hash.into_bytes()).await;

        let backend = RootTokenBackend::new(storage);
        let result = backend.validate("wrong-token").await;

        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_no_hash_stored() {
        let storage = Arc::new(MemoryStorage::new());
        let backend = RootTokenBackend::new(storage);
        let result = backend.validate("any-token").await;

        assert!(matches!(result, Err(AuthError::TokenNotFound)));
    }
}
