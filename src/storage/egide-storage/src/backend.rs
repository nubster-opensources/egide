//! Storage backend trait definition.

use async_trait::async_trait;

use crate::error::StorageError;

/// Storage backend trait for implementing different storage engines.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Get a value by key.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Put a value with a key.
    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Delete a value by key.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// List keys with a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;

    /// Check if a key exists.
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.get(key).await?.is_some())
    }
}
