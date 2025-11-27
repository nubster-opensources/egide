//! # Egide Secrets Engine
//!
//! Key/Value secrets store with versioning, TTL, and rotation support.
//!
//! ## Features
//!
//! - Versioned secrets with rollback capability
//! - TTL and auto-expiration
//! - Soft delete with recovery
//! - Check-and-set (CAS) for optimistic locking
//! - Per-secret encryption with derived keys

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use egide_crypto::{aead, kdf, MasterKey};
use egide_storage_sqlite::SqliteBackend;

pub use error::SecretsError;

/// Domain separation for secret encryption keys.
const SECRET_KEY_INFO_PREFIX: &str = "egide-secrets-v1:";

/// SQL schema for secrets tables.
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS secrets (
    path        TEXT PRIMARY KEY,
    version     INTEGER NOT NULL DEFAULT 1,
    deleted_at  INTEGER,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_versions (
    path        TEXT NOT NULL,
    version     INTEGER NOT NULL,
    data        BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    expires_at  INTEGER,
    metadata    TEXT,
    created_at  INTEGER NOT NULL,
    created_by  TEXT,
    PRIMARY KEY (path, version)
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_path ON secret_versions(path);
"#;

/// A decrypted secret with its data and metadata.
#[derive(Debug, Clone)]
pub struct Secret {
    /// Hierarchical path (e.g., "myapp/database/credentials").
    pub path: String,
    /// Decrypted key-value data.
    pub data: HashMap<String, String>,
    /// Version number.
    pub version: u32,
    /// Optional custom metadata.
    pub metadata: Option<serde_json::Value>,
    /// Creation timestamp of this version.
    pub created_at: u64,
    /// Expiration timestamp (None = never expires).
    pub expires_at: Option<u64>,
}

/// Metadata about a secret (without decrypted data).
#[derive(Debug, Clone)]
pub struct SecretMetadata {
    /// Hierarchical path.
    pub path: String,
    /// Current version number.
    pub version: u32,
    /// Creation timestamp.
    pub created_at: u64,
    /// Last update timestamp.
    pub updated_at: u64,
    /// Whether the secret is soft-deleted.
    pub deleted: bool,
}

/// Options for putting a secret.
#[derive(Debug, Clone, Default)]
pub struct PutOptions {
    /// Time-to-live (secret expires after this duration).
    pub ttl: Option<Duration>,
    /// Custom metadata to store with the secret.
    pub metadata: Option<serde_json::Value>,
    /// Check-and-set: only succeed if current version matches.
    pub cas: Option<u32>,
}

/// Internal structure for storing encrypted secret data.
#[derive(Serialize, Deserialize)]
struct EncryptedSecret {
    data: Vec<u8>,
    nonce: Vec<u8>,
}

/// The Secrets Engine provides secure storage for key-value secrets.
pub struct SecretsEngine {
    storage: SqliteBackend,
    master_key: MasterKey,
}

impl SecretsEngine {
    /// Creates a new SecretsEngine with the given storage path and master key.
    pub async fn new(
        data_path: impl AsRef<Path>,
        tenant: &str,
        master_key: MasterKey,
    ) -> Result<Self, SecretsError> {
        let storage = SqliteBackend::open(data_path, tenant).await?;

        let engine = Self {
            storage,
            master_key,
        };
        engine.init_schema().await?;

        info!(tenant = tenant, "Secrets engine initialized");
        Ok(engine)
    }

    /// Initializes the database schema.
    async fn init_schema(&self) -> Result<(), SecretsError> {
        self.storage
            .execute_raw(SCHEMA)
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Derives an encryption key for a specific secret path.
    fn derive_secret_key(&self, path: &str) -> Result<egide_crypto::SymmetricKey, SecretsError> {
        let info = format!("{}{}", SECRET_KEY_INFO_PREFIX, path);
        let key_bytes = kdf::derive_key(self.master_key.as_bytes(), None, info.as_bytes(), 32)?;
        egide_crypto::SymmetricKey::from_bytes(&key_bytes).map_err(SecretsError::from)
    }

    /// Encrypts secret data for storage.
    fn encrypt_data(
        &self,
        path: &str,
        data: &HashMap<String, String>,
    ) -> Result<(Vec<u8>, Vec<u8>), SecretsError> {
        let key = self.derive_secret_key(path)?;
        let plaintext = serde_json::to_vec(data)
            .map_err(|e| SecretsError::Crypto(format!("serialization failed: {}", e)))?;

        let ciphertext = aead::encrypt(key.as_bytes(), &plaintext, Some(path.as_bytes()))?;

        // Extract nonce from ciphertext (first 12 bytes in our format)
        let nonce = ciphertext[..12].to_vec();
        let data = ciphertext[12..].to_vec();

        Ok((data, nonce))
    }

    /// Decrypts secret data from storage.
    fn decrypt_data(
        &self,
        path: &str,
        data: &[u8],
        nonce: &[u8],
    ) -> Result<HashMap<String, String>, SecretsError> {
        let key = self.derive_secret_key(path)?;

        // Reconstruct ciphertext with nonce prefix
        let mut ciphertext = Vec::with_capacity(nonce.len() + data.len());
        ciphertext.extend_from_slice(nonce);
        ciphertext.extend_from_slice(data);

        let plaintext = aead::decrypt(key.as_bytes(), &ciphertext, Some(path.as_bytes()))?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| SecretsError::Crypto(format!("deserialization failed: {}", e)))
    }

    /// Validates a secret path.
    fn validate_path(path: &str) -> Result<(), SecretsError> {
        if path.is_empty() {
            return Err(SecretsError::InvalidPath("path cannot be empty".into()));
        }
        if path.starts_with('/') || path.ends_with('/') {
            return Err(SecretsError::InvalidPath(
                "path cannot start or end with /".into(),
            ));
        }
        if path.contains("//") {
            return Err(SecretsError::InvalidPath(
                "path cannot contain double slashes".into(),
            ));
        }
        // Allow alphanumeric, hyphens, underscores, and slashes
        if !path
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/')
        {
            return Err(SecretsError::InvalidPath(
                "path contains invalid characters".into(),
            ));
        }
        Ok(())
    }

    /// Returns the current Unix timestamp.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs()
    }

    /// Stores or updates a secret.
    ///
    /// Returns the new version number.
    pub async fn put(
        &self,
        path: &str,
        data: HashMap<String, String>,
        options: PutOptions,
    ) -> Result<u32, SecretsError> {
        Self::validate_path(path)?;

        let now = Self::now();
        let expires_at = options.ttl.map(|ttl| now + ttl.as_secs());
        let metadata_json = options
            .metadata
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| SecretsError::Storage(format!("metadata serialization failed: {}", e)))?;

        // Check if secret exists
        let existing = self
            .storage
            .query_one::<(i64, Option<i64>)>(
                "SELECT version, deleted_at FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        let new_version: u32;

        if let Some((current_version, deleted_at)) = existing {
            // Secret exists
            if deleted_at.is_some() {
                return Err(SecretsError::Deleted(path.to_string()));
            }

            let current_version = current_version as u32;

            // Check CAS if provided
            if let Some(expected) = options.cas {
                if current_version != expected {
                    return Err(SecretsError::VersionMismatch {
                        expected,
                        found: current_version,
                    });
                }
            }

            new_version = current_version + 1;

            // Update secrets table
            self.storage
                .execute(
                    "UPDATE secrets SET version = ?, updated_at = ? WHERE path = ?",
                    &[&(new_version as i64).to_string(), &now.to_string(), path],
                )
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?;
        } else {
            // New secret
            if options.cas.is_some() {
                return Err(SecretsError::NotFound(path.to_string()));
            }

            new_version = 1;

            // Insert into secrets table
            self.storage
                .execute(
                    "INSERT INTO secrets (path, version, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    &[path, &new_version.to_string(), &now.to_string(), &now.to_string()],
                )
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?;
        }

        // Encrypt and store version data
        let (encrypted_data, nonce) = self.encrypt_data(path, &data)?;

        self.storage
            .execute(
                "INSERT INTO secret_versions (path, version, data, nonce, expires_at, metadata, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                &[
                    path,
                    &new_version.to_string(),
                    &hex_encode(&encrypted_data),
                    &hex_encode(&nonce),
                    &expires_at.map(|e| e.to_string()).unwrap_or_default(),
                    &metadata_json.unwrap_or_default(),
                    &now.to_string(),
                    &self.storage.current_actor().unwrap_or_default(),
                ],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        debug!(path = path, version = new_version, "Secret stored");
        Ok(new_version)
    }

    /// Retrieves the current version of a secret.
    pub async fn get(&self, path: &str) -> Result<Secret, SecretsError> {
        Self::validate_path(path)?;

        // Get current version from secrets table
        let row = self
            .storage
            .query_one::<(i64, Option<i64>)>(
                "SELECT version, deleted_at FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::NotFound(path.to_string()))?;

        let (version, deleted_at) = row;
        if deleted_at.is_some() {
            return Err(SecretsError::Deleted(path.to_string()));
        }

        self.get_version(path, version as u32).await
    }

    /// Retrieves a specific version of a secret.
    pub async fn get_version(&self, path: &str, version: u32) -> Result<Secret, SecretsError> {
        Self::validate_path(path)?;

        let row = self
            .storage
            .query_one::<(String, String, String, String, String)>(
                "SELECT data, nonce, COALESCE(CAST(expires_at AS TEXT), ''), COALESCE(metadata, ''), CAST(created_at AS TEXT) FROM secret_versions WHERE path = ? AND version = ?",
                &[path, &version.to_string()],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::VersionNotFound {
                path: path.to_string(),
                version,
            })?;

        let (data_hex, nonce_hex, expires_at_str, metadata_json, created_at_str) = row;

        // Parse timestamps
        let created_at: u64 = created_at_str.parse().unwrap_or(0);
        let expires_at: Option<u64> = if expires_at_str.is_empty() {
            None
        } else {
            expires_at_str.parse().ok()
        };

        // Check expiration
        let now = Self::now();
        if let Some(exp) = expires_at {
            if exp < now {
                return Err(SecretsError::Expired(path.to_string()));
            }
        }

        // Decrypt data
        let data_bytes = hex_decode(&data_hex)
            .map_err(|e| SecretsError::Storage(format!("invalid data encoding: {}", e)))?;
        let nonce_bytes = hex_decode(&nonce_hex)
            .map_err(|e| SecretsError::Storage(format!("invalid nonce encoding: {}", e)))?;

        let data = self.decrypt_data(path, &data_bytes, &nonce_bytes)?;

        let metadata = if metadata_json.is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&metadata_json)
                    .map_err(|e| SecretsError::Storage(format!("invalid metadata: {}", e)))?,
            )
        };

        Ok(Secret {
            path: path.to_string(),
            data,
            version,
            metadata,
            created_at,
            expires_at,
        })
    }

    /// Soft-deletes a secret.
    pub async fn delete(&self, path: &str) -> Result<(), SecretsError> {
        Self::validate_path(path)?;

        let row = self
            .storage
            .query_one::<(i64, Option<i64>)>(
                "SELECT version, deleted_at FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::NotFound(path.to_string()))?;

        let (_, deleted_at) = row;
        if deleted_at.is_some() {
            return Err(SecretsError::Deleted(path.to_string()));
        }

        let now = Self::now();
        self.storage
            .execute(
                "UPDATE secrets SET deleted_at = ? WHERE path = ?",
                &[&now.to_string(), path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        info!(path = path, "Secret deleted");
        Ok(())
    }

    /// Restores a soft-deleted secret.
    pub async fn undelete(&self, path: &str) -> Result<(), SecretsError> {
        Self::validate_path(path)?;

        let row = self
            .storage
            .query_one::<(i64, Option<i64>)>(
                "SELECT version, deleted_at FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::NotFound(path.to_string()))?;

        let (_, deleted_at) = row;
        if deleted_at.is_none() {
            return Err(SecretsError::NotDeleted(path.to_string()));
        }

        self.storage
            .execute(
                "UPDATE secrets SET deleted_at = NULL, updated_at = ? WHERE path = ?",
                &[&Self::now().to_string(), path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        info!(path = path, "Secret restored");
        Ok(())
    }

    /// Lists secrets matching a prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>, SecretsError> {
        let pattern = format!("{}%", prefix);
        let rows = self
            .storage
            .query_all::<(String, String, String, String, String)>(
                "SELECT path, CAST(version AS TEXT), CAST(created_at AS TEXT), CAST(updated_at AS TEXT), COALESCE(CAST(deleted_at AS TEXT), '') FROM secrets WHERE path LIKE ? ORDER BY path",
                &[&pattern],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        let results = rows
            .into_iter()
            .map(
                |(path, version_str, created_at_str, updated_at_str, deleted_at_str)| {
                    SecretMetadata {
                        path,
                        version: version_str.parse().unwrap_or(0),
                        created_at: created_at_str.parse().unwrap_or(0),
                        updated_at: updated_at_str.parse().unwrap_or(0),
                        deleted: !deleted_at_str.is_empty(),
                    }
                },
            )
            .collect();

        Ok(results)
    }

    /// Lists all versions of a secret.
    pub async fn versions(&self, path: &str) -> Result<Vec<SecretVersionInfo>, SecretsError> {
        Self::validate_path(path)?;

        // Check secret exists
        let exists = self
            .storage
            .query_one::<(String,)>("SELECT '1' FROM secrets WHERE path = ?", &[path])
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        if exists.is_none() {
            return Err(SecretsError::NotFound(path.to_string()));
        }

        let rows = self
            .storage
            .query_all::<(String, String, String, String)>(
                "SELECT CAST(version AS TEXT), COALESCE(CAST(expires_at AS TEXT), ''), CAST(created_at AS TEXT), COALESCE(created_by, '') FROM secret_versions WHERE path = ? ORDER BY version DESC",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        let now = Self::now();
        let results = rows
            .into_iter()
            .map(
                |(version_str, expires_at_str, created_at_str, created_by)| {
                    let version: u32 = version_str.parse().unwrap_or(0);
                    let created_at: u64 = created_at_str.parse().unwrap_or(0);
                    let expires_at: Option<u64> = if expires_at_str.is_empty() {
                        None
                    } else {
                        expires_at_str.parse().ok()
                    };
                    let expired = expires_at.map(|e| e < now).unwrap_or(false);
                    SecretVersionInfo {
                        version,
                        created_at,
                        expires_at,
                        created_by: if created_by.is_empty() {
                            None
                        } else {
                            Some(created_by)
                        },
                        expired,
                    }
                },
            )
            .collect();

        Ok(results)
    }

    /// Rolls back to a previous version (creates a new version with old data).
    ///
    /// Returns the new version number.
    pub async fn rollback(&self, path: &str, version: u32) -> Result<u32, SecretsError> {
        // Get the old version's data
        let old_secret = self.get_version(path, version).await?;

        // Put it as a new version
        let new_version = self
            .put(path, old_secret.data, PutOptions::default())
            .await?;

        info!(
            path = path,
            from_version = version,
            to_version = new_version,
            "Secret rolled back"
        );
        Ok(new_version)
    }

    /// Permanently deletes soft-deleted secrets older than the specified duration.
    ///
    /// Returns the number of secrets purged.
    pub async fn purge_deleted(&self, older_than: Duration) -> Result<u32, SecretsError> {
        let cutoff = Self::now() - older_than.as_secs();

        // Get paths to purge
        let paths = self
            .storage
            .query_all::<(String,)>(
                "SELECT path FROM secrets WHERE deleted_at IS NOT NULL AND deleted_at < ?",
                &[&cutoff.to_string()],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        let count = paths.len() as u32;

        for (path,) in paths {
            // Delete versions first
            self.storage
                .execute("DELETE FROM secret_versions WHERE path = ?", &[&path])
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?;

            // Delete secret record
            self.storage
                .execute("DELETE FROM secrets WHERE path = ?", &[&path])
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?;

            debug!(path = path, "Secret purged");
        }

        if count > 0 {
            warn!(count = count, "Purged deleted secrets");
        }

        Ok(count)
    }
}

/// Information about a specific secret version.
#[derive(Debug, Clone)]
pub struct SecretVersionInfo {
    /// Version number.
    pub version: u32,
    /// Creation timestamp.
    pub created_at: u64,
    /// Expiration timestamp.
    pub expires_at: Option<u64>,
    /// Actor who created this version.
    pub created_by: Option<String>,
    /// Whether this version has expired.
    pub expired: bool,
}

/// Encodes bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0F) as usize] as char);
    }
    hex
}

/// Decodes hex to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd length hex string".into());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn setup() -> (TempDir, SecretsEngine) {
        let tmp = TempDir::new().unwrap();
        let master_key = MasterKey::generate();
        let engine = SecretsEngine::new(tmp.path(), "test", master_key)
            .await
            .unwrap();
        (tmp, engine)
    }

    fn test_data() -> HashMap<String, String> {
        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "s3cr3t".to_string());
        data
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let (_tmp, engine) = setup().await;

        let version = engine
            .put("myapp/database", test_data(), PutOptions::default())
            .await
            .unwrap();

        assert_eq!(version, 1);

        let secret = engine.get("myapp/database").await.unwrap();
        assert_eq!(secret.path, "myapp/database");
        assert_eq!(secret.version, 1);
        assert_eq!(secret.data.get("username").unwrap(), "admin");
        assert_eq!(secret.data.get("password").unwrap(), "s3cr3t");
    }

    #[tokio::test]
    async fn test_versioning() {
        let (_tmp, engine) = setup().await;

        // Version 1
        engine
            .put("app/config", test_data(), PutOptions::default())
            .await
            .unwrap();

        // Version 2
        let mut data2 = test_data();
        data2.insert("password".to_string(), "newp4ss".to_string());
        let v2 = engine
            .put("app/config", data2, PutOptions::default())
            .await
            .unwrap();

        assert_eq!(v2, 2);

        // Get current (v2)
        let current = engine.get("app/config").await.unwrap();
        assert_eq!(current.version, 2);
        assert_eq!(current.data.get("password").unwrap(), "newp4ss");

        // Get v1
        let v1 = engine.get_version("app/config", 1).await.unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(v1.data.get("password").unwrap(), "s3cr3t");
    }

    #[tokio::test]
    async fn test_cas_success() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/secret", test_data(), PutOptions::default())
            .await
            .unwrap();

        let opts = PutOptions {
            cas: Some(1),
            ..Default::default()
        };

        let v2 = engine.put("app/secret", test_data(), opts).await.unwrap();
        assert_eq!(v2, 2);
    }

    #[tokio::test]
    async fn test_cas_failure() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/secret", test_data(), PutOptions::default())
            .await
            .unwrap();

        let opts = PutOptions {
            cas: Some(99), // Wrong version
            ..Default::default()
        };

        let result = engine.put("app/secret", test_data(), opts).await;
        assert!(matches!(
            result,
            Err(SecretsError::VersionMismatch {
                expected: 99,
                found: 1
            })
        ));
    }

    #[tokio::test]
    async fn test_delete_and_undelete() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/temp", test_data(), PutOptions::default())
            .await
            .unwrap();

        // Delete
        engine.delete("app/temp").await.unwrap();

        // Should not be accessible
        let result = engine.get("app/temp").await;
        assert!(matches!(result, Err(SecretsError::Deleted(_))));

        // Undelete
        engine.undelete("app/temp").await.unwrap();

        // Should be accessible again
        let secret = engine.get("app/temp").await.unwrap();
        assert_eq!(secret.data.get("username").unwrap(), "admin");
    }

    #[tokio::test]
    async fn test_list() {
        let (_tmp, engine) = setup().await;

        engine
            .put("myapp/db/main", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("myapp/db/replica", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("myapp/cache", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("other/secret", test_data(), PutOptions::default())
            .await
            .unwrap();

        let list = engine.list("myapp/").await.unwrap();
        assert_eq!(list.len(), 3);

        let db_list = engine.list("myapp/db/").await.unwrap();
        assert_eq!(db_list.len(), 2);
    }

    #[tokio::test]
    async fn test_versions_list() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/versioned", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("app/versioned", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("app/versioned", test_data(), PutOptions::default())
            .await
            .unwrap();

        let versions = engine.versions("app/versioned").await.unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, 3); // Descending order
        assert_eq!(versions[2].version, 1);
    }

    #[tokio::test]
    async fn test_rollback() {
        let (_tmp, engine) = setup().await;

        // V1: original
        engine
            .put("app/rollback", test_data(), PutOptions::default())
            .await
            .unwrap();

        // V2: modified
        let mut data2 = HashMap::new();
        data2.insert("key".to_string(), "modified".to_string());
        engine
            .put("app/rollback", data2, PutOptions::default())
            .await
            .unwrap();

        // Rollback to v1
        let v3 = engine.rollback("app/rollback", 1).await.unwrap();
        assert_eq!(v3, 3);

        // V3 should have v1's data
        let secret = engine.get("app/rollback").await.unwrap();
        assert_eq!(secret.version, 3);
        assert_eq!(secret.data.get("username").unwrap(), "admin");
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let (_tmp, engine) = setup().await;

        let opts = PutOptions {
            ttl: Some(Duration::from_secs(1)), // 1 second TTL
            ..Default::default()
        };

        engine.put("app/expiring", test_data(), opts).await.unwrap();

        // Should be accessible immediately
        let result = engine.get("app/expiring").await;
        assert!(result.is_ok());

        // Wait for expiration (need 2+ seconds to account for second-precision timestamps)
        tokio::time::sleep(Duration::from_secs(2)).await;

        let result = engine.get("app/expiring").await;
        assert!(matches!(result, Err(SecretsError::Expired(_))));
    }

    #[tokio::test]
    async fn test_metadata() {
        let (_tmp, engine) = setup().await;

        let metadata = serde_json::json!({
            "owner": "platform-team",
            "rotation_days": 30
        });

        let opts = PutOptions {
            metadata: Some(metadata.clone()),
            ..Default::default()
        };

        engine
            .put("app/with-meta", test_data(), opts)
            .await
            .unwrap();

        let secret = engine.get("app/with-meta").await.unwrap();
        assert_eq!(secret.metadata.unwrap(), metadata);
    }

    #[tokio::test]
    async fn test_invalid_path() {
        let (_tmp, engine) = setup().await;

        let result = engine
            .put("/invalid", test_data(), PutOptions::default())
            .await;
        assert!(matches!(result, Err(SecretsError::InvalidPath(_))));

        let result = engine
            .put("invalid/", test_data(), PutOptions::default())
            .await;
        assert!(matches!(result, Err(SecretsError::InvalidPath(_))));

        let result = engine
            .put("in//valid", test_data(), PutOptions::default())
            .await;
        assert!(matches!(result, Err(SecretsError::InvalidPath(_))));

        let result = engine.put("", test_data(), PutOptions::default()).await;
        assert!(matches!(result, Err(SecretsError::InvalidPath(_))));
    }

    #[tokio::test]
    async fn test_not_found() {
        let (_tmp, engine) = setup().await;

        let result = engine.get("nonexistent").await;
        assert!(matches!(result, Err(SecretsError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_encryption_isolation() {
        // Two engines with different master keys should not be able to read each other's secrets
        let tmp = TempDir::new().unwrap();

        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();

        // Engine 1 writes a secret
        {
            let engine1 = SecretsEngine::new(tmp.path(), "test", key1.clone())
                .await
                .unwrap();
            engine1
                .put("shared/path", test_data(), PutOptions::default())
                .await
                .unwrap();
        }

        // Engine 2 with different key tries to read
        {
            let engine2 = SecretsEngine::new(tmp.path(), "test", key2).await.unwrap();
            let result = engine2.get("shared/path").await;
            // Should fail decryption
            assert!(matches!(result, Err(SecretsError::Crypto(_))));
        }

        // Engine 1 with same key can read
        {
            let engine1 = SecretsEngine::new(tmp.path(), "test", key1).await.unwrap();
            let secret = engine1.get("shared/path").await.unwrap();
            assert_eq!(secret.data.get("username").unwrap(), "admin");
        }
    }
}
