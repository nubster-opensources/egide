//! # Egide Transit Engine
//!
//! Encryption as a Service - applications encrypt/decrypt without seeing keys.
//!
//! ## Features
//!
//! - Encrypt/Decrypt data via API without exposing keys
//! - Key versioning with rotation support
//! - Rewrap (re-encrypt with latest key version)
//! - Datakey generation for envelope encryption
//!
//! ## Ciphertext Format
//!
//! Ciphertexts are encoded as: `egide:v{version}:{base64_ciphertext}`
//!
//! This allows the engine to determine which key version to use for decryption.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::TransitError;

use std::path::Path;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use egide_crypto::{aead, kdf, random, MasterKey};
use egide_storage_sqlite::SqliteBackend;

// ============================================================================
// SQL Schema
// ============================================================================

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS transit_keys (
    name            TEXT PRIMARY KEY,
    key_type        TEXT NOT NULL,
    latest_version  INTEGER NOT NULL DEFAULT 1,
    min_encryption_version INTEGER NOT NULL DEFAULT 1,
    min_decryption_version INTEGER NOT NULL DEFAULT 1,
    supports_encryption INTEGER NOT NULL DEFAULT 1,
    supports_decryption INTEGER NOT NULL DEFAULT 1,
    supports_derivation INTEGER NOT NULL DEFAULT 0,
    exportable      INTEGER NOT NULL DEFAULT 0,
    deletion_allowed INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transit_key_versions (
    name            TEXT NOT NULL,
    version         INTEGER NOT NULL,
    key_material    TEXT NOT NULL,
    nonce           TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    PRIMARY KEY (name, version),
    FOREIGN KEY (name) REFERENCES transit_keys(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_transit_key_versions_name ON transit_key_versions(name);
"#;

// ============================================================================
// Types
// ============================================================================

/// Supported key types for transit encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    /// AES-256-GCM (default, widely compatible).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (fast on systems without AES-NI).
    ChaCha20Poly1305,
}

impl Default for KeyType {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256Gcm => write!(f, "aes256-gcm"),
            Self::ChaCha20Poly1305 => write!(f, "chacha20-poly1305"),
        }
    }
}

impl FromStr for KeyType {
    type Err = TransitError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(TransitError::InvalidKeyType(s.to_string())),
        }
    }
}

/// Configuration for creating a new transit key.
#[derive(Debug, Clone, Default)]
pub struct KeyConfig {
    /// Key type (default: AES-256-GCM).
    pub key_type: KeyType,
    /// Allow encryption operations (default: true).
    pub supports_encryption: bool,
    /// Allow decryption operations (default: true).
    pub supports_decryption: bool,
    /// Allow key derivation (default: false).
    pub supports_derivation: bool,
    /// Allow key export (default: false).
    pub exportable: bool,
    /// Allow key deletion (default: false).
    pub deletion_allowed: bool,
}

impl KeyConfig {
    /// Creates a new KeyConfig with sensible defaults.
    pub fn new() -> Self {
        Self {
            key_type: KeyType::default(),
            supports_encryption: true,
            supports_decryption: true,
            supports_derivation: false,
            exportable: false,
            deletion_allowed: false,
        }
    }
}

/// Metadata about a transit key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitKey {
    /// Key name.
    pub name: String,
    /// Key type.
    pub key_type: KeyType,
    /// Latest (current) version number.
    pub latest_version: u32,
    /// Minimum version allowed for encryption.
    pub min_encryption_version: u32,
    /// Minimum version allowed for decryption.
    pub min_decryption_version: u32,
    /// Whether encryption is supported.
    pub supports_encryption: bool,
    /// Whether decryption is supported.
    pub supports_decryption: bool,
    /// Whether key derivation is supported.
    pub supports_derivation: bool,
    /// Whether the key can be exported.
    pub exportable: bool,
    /// Whether the key can be deleted.
    pub deletion_allowed: bool,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Last update timestamp (Unix seconds).
    pub updated_at: u64,
}

/// Information about a specific key version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersionInfo {
    /// Version number.
    pub version: u32,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}

/// Result of a datakey generation.
#[derive(Debug, Clone)]
pub struct DataKey {
    /// Plaintext key (32 bytes for use by the client).
    pub plaintext: Vec<u8>,
    /// Wrapped (encrypted) key for storage.
    pub ciphertext: String,
}

// ============================================================================
// Hex Encoding Helpers
// ============================================================================

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, TransitError> {
    if s.len() % 2 != 0 {
        return Err(TransitError::Storage("invalid hex length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| TransitError::Storage("invalid hex".into()))
        })
        .collect()
}

// ============================================================================
// Transit Engine
// ============================================================================

/// The Transit Engine provides encryption-as-a-service.
///
/// Applications can encrypt and decrypt data without ever seeing the keys.
pub struct TransitEngine {
    storage: SqliteBackend,
    master_key: MasterKey,
}

impl TransitEngine {
    /// Creates a new TransitEngine with the given storage path and master key.
    pub async fn new(
        data_path: impl AsRef<Path>,
        master_key: MasterKey,
    ) -> Result<Self, TransitError> {
        let storage = SqliteBackend::open(data_path.as_ref(), "transit")
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        // Initialize schema
        storage
            .execute_raw(SCHEMA)
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        info!("Transit engine initialized");

        Ok(Self {
            storage,
            master_key,
        })
    }

    // ========================================================================
    // Key Derivation & Encryption Helpers
    // ========================================================================

    /// Derives a unique encryption key for a transit key version.
    fn derive_version_key(&self, name: &str, version: u32) -> Result<[u8; 32], TransitError> {
        let info = format!("egide-transit-v1:{}:{}", name, version);
        let key = kdf::derive_encryption_key(self.master_key.as_bytes(), info.as_bytes())?;
        Ok(*key)
    }

    /// Encrypts raw key material for storage.
    fn encrypt_key_material(
        &self,
        name: &str,
        version: u32,
        key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), TransitError> {
        let wrapping_key = self.derive_version_key(name, version)?;
        let aad = format!("transit-key:{}:{}", name, version);
        let ciphertext = aead::encrypt(&wrapping_key, key, Some(aad.as_bytes()))?;

        // Split nonce (first 12 bytes) from ciphertext
        let nonce = ciphertext[..12].to_vec();
        let encrypted = ciphertext[12..].to_vec();

        Ok((encrypted, nonce))
    }

    /// Decrypts stored key material.
    fn decrypt_key_material(
        &self,
        name: &str,
        version: u32,
        encrypted: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, TransitError> {
        let wrapping_key = self.derive_version_key(name, version)?;
        let aad = format!("transit-key:{}:{}", name, version);

        // Reconstruct ciphertext with nonce prefix
        let mut ciphertext = Vec::with_capacity(nonce.len() + encrypted.len());
        ciphertext.extend_from_slice(nonce);
        ciphertext.extend_from_slice(encrypted);

        let decrypted = aead::decrypt(&wrapping_key, &ciphertext, Some(aad.as_bytes()))?;
        Ok(decrypted.to_vec())
    }

    /// Gets the raw key material for a specific version.
    async fn get_key_material(&self, name: &str, version: u32) -> Result<Vec<u8>, TransitError> {
        let row = self
            .storage
            .query_one::<(String, String)>(
                "SELECT key_material, nonce FROM transit_key_versions WHERE name = ? AND version = ?",
                &[name, &version.to_string()],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?
            .ok_or_else(|| TransitError::VersionNotFound {
                name: name.to_string(),
                version,
            })?;

        let (key_material_hex, nonce_hex) = row;
        let key_material = hex_decode(&key_material_hex)?;
        let nonce = hex_decode(&nonce_hex)?;

        self.decrypt_key_material(name, version, &key_material, &nonce)
    }

    // ========================================================================
    // Timestamp Helper
    // ========================================================================

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs()
    }

    // ========================================================================
    // Key Name Validation
    // ========================================================================

    fn validate_name(name: &str) -> Result<(), TransitError> {
        if name.is_empty() {
            return Err(TransitError::InvalidKeyName("name cannot be empty".into()));
        }
        if name.len() > 128 {
            return Err(TransitError::InvalidKeyName(
                "name too long (max 128 chars)".into(),
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(TransitError::InvalidKeyName(
                "name can only contain alphanumeric, dash, underscore".into(),
            ));
        }
        Ok(())
    }

    // ========================================================================
    // Key Management Operations
    // ========================================================================

    /// Creates a new transit key.
    pub async fn create_key(
        &self,
        name: &str,
        config: KeyConfig,
    ) -> Result<TransitKey, TransitError> {
        Self::validate_name(name)?;

        // Check if key already exists
        let existing = self
            .storage
            .query_one::<(String,)>("SELECT name FROM transit_keys WHERE name = ?", &[name])
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        if existing.is_some() {
            return Err(TransitError::KeyExists(name.to_string()));
        }

        let now = Self::now();

        // Generate initial key material (32 bytes for AES-256 or ChaCha20)
        let raw_key = random::generate_key();
        let (encrypted_key, nonce) = self.encrypt_key_material(name, 1, raw_key.as_ref())?;

        // Insert key metadata
        self.storage
            .execute(
                "INSERT INTO transit_keys (name, key_type, latest_version, min_encryption_version, min_decryption_version, supports_encryption, supports_decryption, supports_derivation, exportable, deletion_allowed, created_at, updated_at) VALUES (?, ?, 1, 1, 1, ?, ?, ?, ?, ?, ?, ?)",
                &[
                    name,
                    &config.key_type.to_string(),
                    &(config.supports_encryption as i32).to_string(),
                    &(config.supports_decryption as i32).to_string(),
                    &(config.supports_derivation as i32).to_string(),
                    &(config.exportable as i32).to_string(),
                    &(config.deletion_allowed as i32).to_string(),
                    &now.to_string(),
                    &now.to_string(),
                ],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        // Insert initial key version
        self.storage
            .execute(
                "INSERT INTO transit_key_versions (name, version, key_material, nonce, created_at) VALUES (?, 1, ?, ?, ?)",
                &[
                    name,
                    &hex_encode(&encrypted_key),
                    &hex_encode(&nonce),
                    &now.to_string(),
                ],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        info!(name = name, key_type = %config.key_type, "Transit key created");

        Ok(TransitKey {
            name: name.to_string(),
            key_type: config.key_type,
            latest_version: 1,
            min_encryption_version: 1,
            min_decryption_version: 1,
            supports_encryption: config.supports_encryption,
            supports_decryption: config.supports_decryption,
            supports_derivation: config.supports_derivation,
            exportable: config.exportable,
            deletion_allowed: config.deletion_allowed,
            created_at: now,
            updated_at: now,
        })
    }

    /// Gets metadata for a transit key.
    pub async fn get_key(&self, name: &str) -> Result<TransitKey, TransitError> {
        Self::validate_name(name)?;

        let row = self
            .storage
            .query_one::<(String, String, String, String, String, String, String, String, String, String, String, String)>(
                "SELECT name, key_type, CAST(latest_version AS TEXT), CAST(min_encryption_version AS TEXT), CAST(min_decryption_version AS TEXT), CAST(supports_encryption AS TEXT), CAST(supports_decryption AS TEXT), CAST(supports_derivation AS TEXT), CAST(exportable AS TEXT), CAST(deletion_allowed AS TEXT), CAST(created_at AS TEXT), CAST(updated_at AS TEXT) FROM transit_keys WHERE name = ?",
                &[name],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?
            .ok_or_else(|| TransitError::KeyNotFound(name.to_string()))?;

        let (
            name,
            key_type,
            latest_version,
            min_enc,
            min_dec,
            enc,
            dec,
            deriv,
            export,
            del,
            created,
            updated,
        ) = row;

        Ok(TransitKey {
            name,
            key_type: key_type.parse()?,
            latest_version: latest_version.parse().unwrap_or(1),
            min_encryption_version: min_enc.parse().unwrap_or(1),
            min_decryption_version: min_dec.parse().unwrap_or(1),
            supports_encryption: enc.parse::<i32>().unwrap_or(1) != 0,
            supports_decryption: dec.parse::<i32>().unwrap_or(1) != 0,
            supports_derivation: deriv.parse::<i32>().unwrap_or(0) != 0,
            exportable: export.parse::<i32>().unwrap_or(0) != 0,
            deletion_allowed: del.parse::<i32>().unwrap_or(0) != 0,
            created_at: created.parse().unwrap_or(0),
            updated_at: updated.parse().unwrap_or(0),
        })
    }

    /// Lists all transit key names.
    pub async fn list_keys(&self) -> Result<Vec<String>, TransitError> {
        let rows = self
            .storage
            .query_all::<(String,)>("SELECT name FROM transit_keys ORDER BY name", &[])
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// Lists all versions of a key.
    pub async fn list_versions(&self, name: &str) -> Result<Vec<KeyVersionInfo>, TransitError> {
        Self::validate_name(name)?;

        // Verify key exists
        let _ = self.get_key(name).await?;

        let rows = self
            .storage
            .query_all::<(String, String)>(
                "SELECT CAST(version AS TEXT), CAST(created_at AS TEXT) FROM transit_key_versions WHERE name = ? ORDER BY version DESC",
                &[name],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|(version, created_at)| KeyVersionInfo {
                version: version.parse().unwrap_or(0),
                created_at: created_at.parse().unwrap_or(0),
            })
            .collect())
    }

    /// Rotates a key to a new version.
    pub async fn rotate_key(&self, name: &str) -> Result<u32, TransitError> {
        Self::validate_name(name)?;

        let key = self.get_key(name).await?;
        let new_version = key.latest_version + 1;
        let now = Self::now();

        // Generate new key material
        let raw_key = random::generate_key();
        let (encrypted_key, nonce) =
            self.encrypt_key_material(name, new_version, raw_key.as_ref())?;

        // Insert new version
        self.storage
            .execute(
                "INSERT INTO transit_key_versions (name, version, key_material, nonce, created_at) VALUES (?, ?, ?, ?, ?)",
                &[
                    name,
                    &new_version.to_string(),
                    &hex_encode(&encrypted_key),
                    &hex_encode(&nonce),
                    &now.to_string(),
                ],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        // Update latest version
        self.storage
            .execute(
                "UPDATE transit_keys SET latest_version = ?, updated_at = ? WHERE name = ?",
                &[&new_version.to_string(), &now.to_string(), name],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        info!(name = name, version = new_version, "Transit key rotated");

        Ok(new_version)
    }

    /// Deletes a transit key (if deletion is allowed).
    pub async fn delete_key(&self, name: &str) -> Result<(), TransitError> {
        Self::validate_name(name)?;

        let key = self.get_key(name).await?;

        if !key.deletion_allowed {
            return Err(TransitError::DeletionNotAllowed(name.to_string()));
        }

        // Delete versions first (foreign key)
        self.storage
            .execute("DELETE FROM transit_key_versions WHERE name = ?", &[name])
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        // Delete key
        self.storage
            .execute("DELETE FROM transit_keys WHERE name = ?", &[name])
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        warn!(name = name, "Transit key deleted");

        Ok(())
    }

    /// Updates key configuration (min versions, etc.).
    pub async fn update_key_config(
        &self,
        name: &str,
        min_encryption_version: Option<u32>,
        min_decryption_version: Option<u32>,
        deletion_allowed: Option<bool>,
    ) -> Result<(), TransitError> {
        Self::validate_name(name)?;

        let key = self.get_key(name).await?;
        let now = Self::now();

        let min_enc = min_encryption_version.unwrap_or(key.min_encryption_version);
        let min_dec = min_decryption_version.unwrap_or(key.min_decryption_version);
        let del = deletion_allowed.unwrap_or(key.deletion_allowed);

        // Validate: min versions cannot exceed latest version
        if min_enc > key.latest_version {
            return Err(TransitError::VersionNotFound {
                name: name.to_string(),
                version: min_enc,
            });
        }
        if min_dec > key.latest_version {
            return Err(TransitError::VersionNotFound {
                name: name.to_string(),
                version: min_dec,
            });
        }

        self.storage
            .execute(
                "UPDATE transit_keys SET min_encryption_version = ?, min_decryption_version = ?, deletion_allowed = ?, updated_at = ? WHERE name = ?",
                &[
                    &min_enc.to_string(),
                    &min_dec.to_string(),
                    &(del as i32).to_string(),
                    &now.to_string(),
                    name,
                ],
            )
            .await
            .map_err(|e| TransitError::Storage(e.to_string()))?;

        debug!(name = name, "Transit key config updated");

        Ok(())
    }

    // ========================================================================
    // Encryption/Decryption Operations
    // ========================================================================

    /// Encrypts plaintext using the latest version of a key.
    ///
    /// Returns ciphertext in format: `egide:v{version}:{base64}`
    pub async fn encrypt(&self, name: &str, plaintext: &[u8]) -> Result<String, TransitError> {
        let key = self.get_key(name).await?;

        if !key.supports_encryption {
            return Err(TransitError::OperationNotAllowed(
                "encryption not allowed for this key".into(),
            ));
        }

        self.encrypt_with_version(name, plaintext, key.latest_version)
            .await
    }

    /// Encrypts plaintext using a specific key version.
    pub async fn encrypt_with_version(
        &self,
        name: &str,
        plaintext: &[u8],
        version: u32,
    ) -> Result<String, TransitError> {
        let key = self.get_key(name).await?;

        if !key.supports_encryption {
            return Err(TransitError::OperationNotAllowed(
                "encryption not allowed for this key".into(),
            ));
        }

        if version < key.min_encryption_version {
            return Err(TransitError::VersionBelowMinEncryption {
                version,
                min: key.min_encryption_version,
            });
        }

        if version > key.latest_version {
            return Err(TransitError::VersionNotFound {
                name: name.to_string(),
                version,
            });
        }

        // Get the raw key material
        let raw_key = self.get_key_material(name, version).await?;

        // Encrypt with AAD containing key name for domain separation
        let aad = format!("egide-transit:{}:{}", name, version);
        let ciphertext = aead::encrypt(&raw_key, plaintext, Some(aad.as_bytes()))?;

        // Format: egide:v{version}:{base64}
        let encoded = BASE64.encode(&ciphertext);
        Ok(format!("egide:v{}:{}", version, encoded))
    }

    /// Decrypts ciphertext.
    ///
    /// Automatically determines the key version from the ciphertext format.
    pub async fn decrypt(&self, name: &str, ciphertext: &str) -> Result<Vec<u8>, TransitError> {
        let key = self.get_key(name).await?;

        if !key.supports_decryption {
            return Err(TransitError::OperationNotAllowed(
                "decryption not allowed for this key".into(),
            ));
        }

        // Parse ciphertext format: egide:v{version}:{base64}
        let (version, data) = Self::parse_ciphertext(ciphertext)?;

        if version < key.min_decryption_version {
            return Err(TransitError::VersionBelowMinDecryption {
                version,
                min: key.min_decryption_version,
            });
        }

        // Get the raw key material for this version
        let raw_key = self.get_key_material(name, version).await?;

        // Decrypt with AAD
        let aad = format!("egide-transit:{}:{}", name, version);
        let decrypted = aead::decrypt(&raw_key, &data, Some(aad.as_bytes()))
            .map_err(|_| TransitError::DecryptionFailed)?;
        Ok(decrypted.to_vec())
    }

    /// Parses the ciphertext format and extracts version and raw data.
    fn parse_ciphertext(ciphertext: &str) -> Result<(u32, Vec<u8>), TransitError> {
        let parts: Vec<&str> = ciphertext.splitn(3, ':').collect();

        if parts.len() != 3 || parts[0] != "egide" {
            return Err(TransitError::InvalidCiphertext);
        }

        let version_str = parts[1]
            .strip_prefix('v')
            .ok_or(TransitError::InvalidCiphertext)?;
        let version: u32 = version_str
            .parse()
            .map_err(|_| TransitError::InvalidCiphertext)?;

        let data = BASE64
            .decode(parts[2])
            .map_err(|_| TransitError::InvalidCiphertext)?;

        Ok((version, data))
    }

    /// Rewraps ciphertext with the latest key version.
    ///
    /// This decrypts and re-encrypts without exposing plaintext to the caller.
    pub async fn rewrap(&self, name: &str, ciphertext: &str) -> Result<String, TransitError> {
        let key = self.get_key(name).await?;

        // Parse to get current version
        let (current_version, _) = Self::parse_ciphertext(ciphertext)?;

        // If already at latest version, return as-is
        if current_version == key.latest_version {
            return Ok(ciphertext.to_string());
        }

        // Decrypt with old version, encrypt with new
        let plaintext = self.decrypt(name, ciphertext).await?;
        self.encrypt(name, &plaintext).await
    }

    // ========================================================================
    // Datakey Generation
    // ========================================================================

    /// Generates a new data encryption key (DEK).
    ///
    /// Returns both the plaintext key (for immediate use) and the wrapped key
    /// (for storage). The plaintext key should be used and then discarded.
    pub async fn generate_datakey(&self, name: &str) -> Result<DataKey, TransitError> {
        let key = self.get_key(name).await?;

        if !key.supports_encryption {
            return Err(TransitError::OperationNotAllowed(
                "datakey generation requires encryption capability".into(),
            ));
        }

        // Generate a random 32-byte key
        let plaintext_key = random::generate_key();

        // Wrap it with the transit key
        let wrapped = self.encrypt(name, plaintext_key.as_ref()).await?;

        Ok(DataKey {
            plaintext: plaintext_key.to_vec(),
            ciphertext: wrapped,
        })
    }

    /// Decrypts a wrapped data key.
    pub async fn decrypt_datakey(
        &self,
        name: &str,
        wrapped: &str,
    ) -> Result<Vec<u8>, TransitError> {
        self.decrypt(name, wrapped).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn setup() -> (TempDir, TransitEngine) {
        let tmp = TempDir::new().unwrap();
        let master_key = MasterKey::generate();
        let engine = TransitEngine::new(tmp.path(), master_key).await.unwrap();
        (tmp, engine)
    }

    #[tokio::test]
    async fn test_create_and_get_key() {
        let (_tmp, engine) = setup().await;

        let key = engine.create_key("my-key", KeyConfig::new()).await.unwrap();
        assert_eq!(key.name, "my-key");
        assert_eq!(key.key_type, KeyType::Aes256Gcm);
        assert_eq!(key.latest_version, 1);
        assert!(key.supports_encryption);
        assert!(key.supports_decryption);

        let retrieved = engine.get_key("my-key").await.unwrap();
        assert_eq!(retrieved.name, "my-key");
    }

    #[tokio::test]
    async fn test_key_already_exists() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("dup-key", KeyConfig::new())
            .await
            .unwrap();
        let result = engine.create_key("dup-key", KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::KeyExists(_))));
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let (_tmp, engine) = setup().await;

        let result = engine.get_key("nonexistent").await;
        assert!(matches!(result, Err(TransitError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_invalid_key_name() {
        let (_tmp, engine) = setup().await;

        let result = engine.create_key("", KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::InvalidKeyName(_))));

        let result = engine.create_key("key with spaces", KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::InvalidKeyName(_))));
    }

    #[tokio::test]
    async fn test_list_keys() {
        let (_tmp, engine) = setup().await;

        engine.create_key("alpha", KeyConfig::new()).await.unwrap();
        engine.create_key("beta", KeyConfig::new()).await.unwrap();
        engine.create_key("gamma", KeyConfig::new()).await.unwrap();

        let keys = engine.list_keys().await.unwrap();
        assert_eq!(keys, vec!["alpha", "beta", "gamma"]);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("enc-key", KeyConfig::new())
            .await
            .unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = engine.encrypt("enc-key", plaintext).await.unwrap();

        assert!(ciphertext.starts_with("egide:v1:"));

        let decrypted = engine.decrypt("enc-key", &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_large_data() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("large-key", KeyConfig::new())
            .await
            .unwrap();

        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let ciphertext = engine.encrypt("large-key", &plaintext).await.unwrap();
        let decrypted = engine.decrypt("large-key", &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("rotate-key", KeyConfig::new())
            .await
            .unwrap();

        // Encrypt with v1
        let ciphertext_v1 = engine.encrypt("rotate-key", b"secret").await.unwrap();
        assert!(ciphertext_v1.starts_with("egide:v1:"));

        // Rotate
        let new_version = engine.rotate_key("rotate-key").await.unwrap();
        assert_eq!(new_version, 2);

        // Encrypt with v2
        let ciphertext_v2 = engine.encrypt("rotate-key", b"secret").await.unwrap();
        assert!(ciphertext_v2.starts_with("egide:v2:"));

        // Both should still decrypt
        let decrypted_v1 = engine.decrypt("rotate-key", &ciphertext_v1).await.unwrap();
        let decrypted_v2 = engine.decrypt("rotate-key", &ciphertext_v2).await.unwrap();
        assert_eq!(decrypted_v1, b"secret");
        assert_eq!(decrypted_v2, b"secret");
    }

    #[tokio::test]
    async fn test_rewrap() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("rewrap-key", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext_v1 = engine.encrypt("rewrap-key", b"data").await.unwrap();
        assert!(ciphertext_v1.starts_with("egide:v1:"));

        // Rotate key
        engine.rotate_key("rewrap-key").await.unwrap();

        // Rewrap
        let ciphertext_v2 = engine.rewrap("rewrap-key", &ciphertext_v1).await.unwrap();
        assert!(ciphertext_v2.starts_with("egide:v2:"));

        // Verify data unchanged
        let decrypted = engine.decrypt("rewrap-key", &ciphertext_v2).await.unwrap();
        assert_eq!(decrypted, b"data");
    }

    #[tokio::test]
    async fn test_min_decryption_version() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("min-dec", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext_v1 = engine.encrypt("min-dec", b"old").await.unwrap();

        // Rotate and update min_decryption_version
        engine.rotate_key("min-dec").await.unwrap();
        engine
            .update_key_config("min-dec", None, Some(2), None)
            .await
            .unwrap();

        // v1 ciphertext should fail
        let result = engine.decrypt("min-dec", &ciphertext_v1).await;
        assert!(matches!(
            result,
            Err(TransitError::VersionBelowMinDecryption { .. })
        ));
    }

    #[tokio::test]
    async fn test_delete_key() {
        let (_tmp, engine) = setup().await;

        // Create with deletion_allowed = false (default)
        engine
            .create_key("no-delete", KeyConfig::new())
            .await
            .unwrap();
        let result = engine.delete_key("no-delete").await;
        assert!(matches!(result, Err(TransitError::DeletionNotAllowed(_))));

        // Create with deletion_allowed = true
        let mut config = KeyConfig::new();
        config.deletion_allowed = true;
        engine.create_key("can-delete", config).await.unwrap();
        engine.delete_key("can-delete").await.unwrap();

        let result = engine.get_key("can-delete").await;
        assert!(matches!(result, Err(TransitError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_generate_datakey() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("dek-key", KeyConfig::new())
            .await
            .unwrap();

        let datakey = engine.generate_datakey("dek-key").await.unwrap();
        assert_eq!(datakey.plaintext.len(), 32);
        assert!(datakey.ciphertext.starts_with("egide:v1:"));

        // Verify we can decrypt the wrapped key
        let decrypted = engine
            .decrypt_datakey("dek-key", &datakey.ciphertext)
            .await
            .unwrap();
        assert_eq!(decrypted, datakey.plaintext);
    }

    #[tokio::test]
    async fn test_encryption_disabled() {
        let (_tmp, engine) = setup().await;

        let mut config = KeyConfig::new();
        config.supports_encryption = false;

        engine.create_key("no-enc", config).await.unwrap();

        let result = engine.encrypt("no-enc", b"data").await;
        assert!(matches!(result, Err(TransitError::OperationNotAllowed(_))));
    }

    #[tokio::test]
    async fn test_decryption_disabled() {
        let (_tmp, engine) = setup().await;

        // Create key, encrypt something, then test with a decrypt-disabled key
        engine
            .create_key("enc-only", KeyConfig::new())
            .await
            .unwrap();
        let ciphertext = engine.encrypt("enc-only", b"data").await.unwrap();

        // Create a new engine to test with a decrypt-disabled key
        let (_tmp2, engine2) = setup().await;
        let mut config = KeyConfig::new();
        config.supports_decryption = false;
        engine2.create_key("no-dec", config).await.unwrap();

        let result = engine2.decrypt("no-dec", &ciphertext).await;
        assert!(matches!(result, Err(TransitError::OperationNotAllowed(_))));
    }

    #[tokio::test]
    async fn test_invalid_ciphertext() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("test-key", KeyConfig::new())
            .await
            .unwrap();

        let result = engine.decrypt("test-key", "invalid").await;
        assert!(matches!(result, Err(TransitError::InvalidCiphertext)));

        let result = engine.decrypt("test-key", "not:a:valid:format").await;
        assert!(matches!(result, Err(TransitError::InvalidCiphertext)));

        let result = engine
            .decrypt("test-key", "egide:v1:!!!invalid-base64!!!")
            .await;
        assert!(matches!(result, Err(TransitError::InvalidCiphertext)));
    }

    #[tokio::test]
    async fn test_key_isolation() {
        let (_tmp, engine) = setup().await;

        engine.create_key("key-a", KeyConfig::new()).await.unwrap();
        engine.create_key("key-b", KeyConfig::new()).await.unwrap();

        let ciphertext = engine.encrypt("key-a", b"secret").await.unwrap();

        // Should fail when trying to decrypt with different key
        let result = engine.decrypt("key-b", &ciphertext).await;
        assert!(matches!(result, Err(TransitError::DecryptionFailed)));
    }

    #[tokio::test]
    async fn test_list_versions() {
        let (_tmp, engine) = setup().await;

        engine
            .create_key("ver-key", KeyConfig::new())
            .await
            .unwrap();
        engine.rotate_key("ver-key").await.unwrap();
        engine.rotate_key("ver-key").await.unwrap();

        let versions = engine.list_versions("ver-key").await.unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version, 3); // Most recent first
        assert_eq!(versions[1].version, 2);
        assert_eq!(versions[2].version, 1);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[tokio::test]
    async fn test_encrypt_empty_data() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("empty-key", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext = engine.encrypt("empty-key", b"").await.unwrap();
        let decrypted = engine.decrypt("empty-key", &ciphertext).await.unwrap();
        assert_eq!(decrypted, b"");
    }

    #[tokio::test]
    async fn test_encrypt_binary_data() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("bin-key", KeyConfig::new())
            .await
            .unwrap();

        // All possible byte values
        let binary_data: Vec<u8> = (0..=255).collect();
        let ciphertext = engine.encrypt("bin-key", &binary_data).await.unwrap();
        let decrypted = engine.decrypt("bin-key", &ciphertext).await.unwrap();
        assert_eq!(decrypted, binary_data);
    }

    #[tokio::test]
    async fn test_encrypt_unicode_data() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("unicode-key", KeyConfig::new())
            .await
            .unwrap();

        let unicode_data = "Hello 世界! 🔐 Ægide résiste aux attaques! 日本語テスト";
        let ciphertext = engine
            .encrypt("unicode-key", unicode_data.as_bytes())
            .await
            .unwrap();
        let decrypted = engine.decrypt("unicode-key", &ciphertext).await.unwrap();
        assert_eq!(String::from_utf8(decrypted).unwrap(), unicode_data);
    }

    #[tokio::test]
    async fn test_key_name_max_length() {
        let (_tmp, engine) = setup().await;

        // 128 chars should work
        let max_name: String = "a".repeat(128);
        engine
            .create_key(&max_name, KeyConfig::new())
            .await
            .unwrap();

        // 129 chars should fail
        let too_long: String = "a".repeat(129);
        let result = engine.create_key(&too_long, KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::InvalidKeyName(_))));
    }

    #[tokio::test]
    async fn test_key_name_allowed_chars() {
        let (_tmp, engine) = setup().await;

        // These should all work
        engine.create_key("my-key", KeyConfig::new()).await.unwrap();
        engine.create_key("my_key", KeyConfig::new()).await.unwrap();
        engine
            .create_key("MyKey123", KeyConfig::new())
            .await
            .unwrap();
        engine
            .create_key("KEY-2024_test", KeyConfig::new())
            .await
            .unwrap();

        // These should fail
        let result = engine.create_key("key/path", KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::InvalidKeyName(_))));

        let result = engine.create_key("key.name", KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::InvalidKeyName(_))));

        let result = engine.create_key("key name", KeyConfig::new()).await;
        assert!(matches!(result, Err(TransitError::InvalidKeyName(_))));
    }

    // ========================================================================
    // Version Boundary Tests
    // ========================================================================

    #[tokio::test]
    async fn test_encrypt_with_specific_version() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("ver-enc", KeyConfig::new())
            .await
            .unwrap();
        engine.rotate_key("ver-enc").await.unwrap();
        engine.rotate_key("ver-enc").await.unwrap();

        // Encrypt with v2 (not latest)
        let ciphertext = engine
            .encrypt_with_version("ver-enc", b"data", 2)
            .await
            .unwrap();
        assert!(ciphertext.starts_with("egide:v2:"));

        // Should decrypt correctly
        let decrypted = engine.decrypt("ver-enc", &ciphertext).await.unwrap();
        assert_eq!(decrypted, b"data");
    }

    #[tokio::test]
    async fn test_min_encryption_version() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("min-enc", KeyConfig::new())
            .await
            .unwrap();
        engine.rotate_key("min-enc").await.unwrap();

        // Set min_encryption_version to 2
        engine
            .update_key_config("min-enc", Some(2), None, None)
            .await
            .unwrap();

        // Encrypting with v1 should fail
        let result = engine.encrypt_with_version("min-enc", b"data", 1).await;
        assert!(matches!(
            result,
            Err(TransitError::VersionBelowMinEncryption { .. })
        ));

        // Encrypting with v2 should work
        let ciphertext = engine
            .encrypt_with_version("min-enc", b"data", 2)
            .await
            .unwrap();
        assert!(ciphertext.starts_with("egide:v2:"));
    }

    #[tokio::test]
    async fn test_encrypt_with_nonexistent_version() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("noversion", KeyConfig::new())
            .await
            .unwrap();

        // Try to encrypt with version 99
        let result = engine.encrypt_with_version("noversion", b"data", 99).await;
        assert!(matches!(result, Err(TransitError::VersionNotFound { .. })));
    }

    #[tokio::test]
    async fn test_rewrap_already_latest() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("rewrap-latest", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext = engine.encrypt("rewrap-latest", b"data").await.unwrap();

        // Rewrap should return same ciphertext (already at latest)
        let rewrapped = engine.rewrap("rewrap-latest", &ciphertext).await.unwrap();
        assert_eq!(rewrapped, ciphertext);
    }

    #[tokio::test]
    async fn test_multiple_rotations() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("multi-rot", KeyConfig::new())
            .await
            .unwrap();

        // Encrypt with each version
        let ct1 = engine.encrypt("multi-rot", b"v1-data").await.unwrap();

        engine.rotate_key("multi-rot").await.unwrap();
        let ct2 = engine.encrypt("multi-rot", b"v2-data").await.unwrap();

        engine.rotate_key("multi-rot").await.unwrap();
        let ct3 = engine.encrypt("multi-rot", b"v3-data").await.unwrap();

        engine.rotate_key("multi-rot").await.unwrap();
        let ct4 = engine.encrypt("multi-rot", b"v4-data").await.unwrap();

        engine.rotate_key("multi-rot").await.unwrap();
        let ct5 = engine.encrypt("multi-rot", b"v5-data").await.unwrap();

        // All should decrypt correctly
        assert_eq!(engine.decrypt("multi-rot", &ct1).await.unwrap(), b"v1-data");
        assert_eq!(engine.decrypt("multi-rot", &ct2).await.unwrap(), b"v2-data");
        assert_eq!(engine.decrypt("multi-rot", &ct3).await.unwrap(), b"v3-data");
        assert_eq!(engine.decrypt("multi-rot", &ct4).await.unwrap(), b"v4-data");
        assert_eq!(engine.decrypt("multi-rot", &ct5).await.unwrap(), b"v5-data");

        // Verify version numbers
        assert!(ct1.starts_with("egide:v1:"));
        assert!(ct5.starts_with("egide:v5:"));
    }

    // ========================================================================
    // Error Condition Tests
    // ========================================================================

    #[tokio::test]
    async fn test_tampered_ciphertext_base64() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("tamper-key", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext = engine.encrypt("tamper-key", b"secret").await.unwrap();

        // Tamper with the base64 payload
        let parts: Vec<&str> = ciphertext.splitn(3, ':').collect();
        let tampered = format!("{}:{}:{}TAMPERED", parts[0], parts[1], parts[2]);

        let result = engine.decrypt("tamper-key", &tampered).await;
        // Could be InvalidCiphertext (bad base64) or DecryptionFailed (bad auth tag)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tampered_ciphertext_bytes() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("tamper-bytes", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext = engine.encrypt("tamper-bytes", b"secret").await.unwrap();

        // Decode, flip a bit, re-encode
        let parts: Vec<&str> = ciphertext.splitn(3, ':').collect();
        let mut bytes = BASE64.decode(parts[2]).unwrap();
        if !bytes.is_empty() {
            bytes[0] ^= 0xFF; // Flip bits
        }
        let tampered = format!("{}:{}:{}", parts[0], parts[1], BASE64.encode(&bytes));

        let result = engine.decrypt("tamper-bytes", &tampered).await;
        assert!(matches!(result, Err(TransitError::DecryptionFailed)));
    }

    #[tokio::test]
    async fn test_wrong_version_in_ciphertext() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("wrong-ver", KeyConfig::new())
            .await
            .unwrap();

        let ciphertext = engine.encrypt("wrong-ver", b"data").await.unwrap();

        // Change version number in ciphertext from v1 to v2
        let fake_v2 = ciphertext.replace("egide:v1:", "egide:v2:");

        // Should fail - v2 doesn't exist
        let result = engine.decrypt("wrong-ver", &fake_v2).await;
        assert!(matches!(result, Err(TransitError::VersionNotFound { .. })));
    }

    #[tokio::test]
    async fn test_update_config_invalid_version() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("cfg-ver", KeyConfig::new())
            .await
            .unwrap();

        // Try to set min_encryption_version higher than latest
        let result = engine
            .update_key_config("cfg-ver", Some(99), None, None)
            .await;
        assert!(matches!(result, Err(TransitError::VersionNotFound { .. })));

        // Try to set min_decryption_version higher than latest
        let result = engine
            .update_key_config("cfg-ver", None, Some(99), None)
            .await;
        assert!(matches!(result, Err(TransitError::VersionNotFound { .. })));
    }

    #[tokio::test]
    async fn test_list_versions_nonexistent_key() {
        let (_tmp, engine) = setup().await;

        let result = engine.list_versions("nonexistent").await;
        assert!(matches!(result, Err(TransitError::KeyNotFound(_))));
    }

    // ========================================================================
    // Integration Tests - Full Workflows
    // ========================================================================

    #[tokio::test]
    async fn test_full_lifecycle() {
        let (_tmp, engine) = setup().await;

        // 1. Create key
        let key = engine
            .create_key("lifecycle", KeyConfig::new())
            .await
            .unwrap();
        assert_eq!(key.latest_version, 1);

        // 2. Encrypt some data
        let ct1 = engine
            .encrypt("lifecycle", b"initial-secret")
            .await
            .unwrap();

        // 3. Rotate key
        let v2 = engine.rotate_key("lifecycle").await.unwrap();
        assert_eq!(v2, 2);

        // 4. Encrypt more data with new version
        let ct2 = engine.encrypt("lifecycle", b"new-secret").await.unwrap();

        // 5. Both should decrypt
        assert_eq!(
            engine.decrypt("lifecycle", &ct1).await.unwrap(),
            b"initial-secret"
        );
        assert_eq!(
            engine.decrypt("lifecycle", &ct2).await.unwrap(),
            b"new-secret"
        );

        // 6. Rewrap old ciphertext
        let ct1_rewrapped = engine.rewrap("lifecycle", &ct1).await.unwrap();
        assert!(ct1_rewrapped.starts_with("egide:v2:"));
        assert_eq!(
            engine.decrypt("lifecycle", &ct1_rewrapped).await.unwrap(),
            b"initial-secret"
        );

        // 7. Update min_decryption_version to deprecate v1
        engine
            .update_key_config("lifecycle", None, Some(2), None)
            .await
            .unwrap();

        // 8. Old ct1 should now fail
        let result = engine.decrypt("lifecycle", &ct1).await;
        assert!(matches!(
            result,
            Err(TransitError::VersionBelowMinDecryption { .. })
        ));

        // 9. Rewrapped version should still work
        assert_eq!(
            engine.decrypt("lifecycle", &ct1_rewrapped).await.unwrap(),
            b"initial-secret"
        );
    }

    #[tokio::test]
    async fn test_envelope_encryption_workflow() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("envelope-kek", KeyConfig::new())
            .await
            .unwrap();

        // Simulate envelope encryption workflow
        // 1. Generate a data key
        let datakey = engine.generate_datakey("envelope-kek").await.unwrap();

        // 2. Client uses plaintext key to encrypt their data (simulated)
        let client_data = b"sensitive application data";
        let client_encrypted =
            egide_crypto::aead::encrypt(&datakey.plaintext, client_data, Some(b"app-context"))
                .unwrap();

        // 3. Client stores wrapped key alongside their encrypted data
        let stored_wrapped_key = datakey.ciphertext.clone();

        // 4. Later, client needs to decrypt
        // 4a. Unwrap the data key
        let recovered_dek = engine
            .decrypt_datakey("envelope-kek", &stored_wrapped_key)
            .await
            .unwrap();
        assert_eq!(recovered_dek, datakey.plaintext);

        // 4b. Client decrypts their data with recovered key
        let decrypted =
            egide_crypto::aead::decrypt(&recovered_dek, &client_encrypted, Some(b"app-context"))
                .unwrap();
        assert_eq!(&decrypted[..], client_data);
    }

    #[tokio::test]
    async fn test_multi_key_workflow() {
        let (_tmp, engine) = setup().await;

        // Create keys for different purposes
        engine
            .create_key("users-key", KeyConfig::new())
            .await
            .unwrap();
        engine
            .create_key("payments-key", KeyConfig::new())
            .await
            .unwrap();
        engine
            .create_key("logs-key", KeyConfig::new())
            .await
            .unwrap();

        // Encrypt different data types
        let user_ct = engine
            .encrypt("users-key", b"user@email.com")
            .await
            .unwrap();
        let payment_ct = engine
            .encrypt("payments-key", b"4111111111111111")
            .await
            .unwrap();
        let log_ct = engine
            .encrypt("logs-key", b"debug log entry")
            .await
            .unwrap();

        // Verify isolation - can't cross-decrypt
        assert!(engine.decrypt("payments-key", &user_ct).await.is_err());
        assert!(engine.decrypt("logs-key", &payment_ct).await.is_err());
        assert!(engine.decrypt("users-key", &log_ct).await.is_err());

        // Correct decryption works
        assert_eq!(
            engine.decrypt("users-key", &user_ct).await.unwrap(),
            b"user@email.com"
        );
        assert_eq!(
            engine.decrypt("payments-key", &payment_ct).await.unwrap(),
            b"4111111111111111"
        );
        assert_eq!(
            engine.decrypt("logs-key", &log_ct).await.unwrap(),
            b"debug log entry"
        );
    }

    // ========================================================================
    // Persistence Tests
    // ========================================================================

    #[tokio::test]
    async fn test_persistence_across_restart() {
        let tmp = TempDir::new().unwrap();
        let master_key = MasterKey::generate();
        let master_key_bytes = master_key.as_bytes().to_vec();

        // First session: create key and encrypt
        let ciphertext = {
            let engine = TransitEngine::new(tmp.path(), master_key).await.unwrap();
            engine
                .create_key("persist-key", KeyConfig::new())
                .await
                .unwrap();
            engine.rotate_key("persist-key").await.unwrap();
            engine
                .encrypt("persist-key", b"persisted-data")
                .await
                .unwrap()
        };
        // Engine dropped here

        // Second session: recover with same master key
        {
            let master_key2 = MasterKey::from_bytes(&master_key_bytes).unwrap();
            let engine2 = TransitEngine::new(tmp.path(), master_key2).await.unwrap();

            // Key should exist
            let key = engine2.get_key("persist-key").await.unwrap();
            assert_eq!(key.latest_version, 2);

            // Should decrypt data from previous session
            let decrypted = engine2.decrypt("persist-key", &ciphertext).await.unwrap();
            assert_eq!(decrypted, b"persisted-data");

            // Should be able to continue rotating
            let v3 = engine2.rotate_key("persist-key").await.unwrap();
            assert_eq!(v3, 3);
        }
    }

    #[tokio::test]
    async fn test_wrong_master_key_fails() {
        let tmp = TempDir::new().unwrap();

        // First session: create and encrypt
        let ciphertext = {
            let master_key1 = MasterKey::generate();
            let engine = TransitEngine::new(tmp.path(), master_key1).await.unwrap();
            engine
                .create_key("wrong-mk", KeyConfig::new())
                .await
                .unwrap();
            engine.encrypt("wrong-mk", b"data").await.unwrap()
        };

        // Second session: different master key
        {
            let master_key2 = MasterKey::generate(); // Different key!
            let engine2 = TransitEngine::new(tmp.path(), master_key2).await.unwrap();

            // Key metadata exists but decryption should fail
            let key = engine2.get_key("wrong-mk").await.unwrap();
            assert_eq!(key.name, "wrong-mk");

            // Decryption fails because key material was encrypted with different master
            let result = engine2.decrypt("wrong-mk", &ciphertext).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_concurrent_encryptions() {
        let (_tmp, engine) = setup().await;
        engine
            .create_key("concurrent", KeyConfig::new())
            .await
            .unwrap();

        // Encrypt many items "concurrently" (sequential in test but simulates load)
        let mut ciphertexts = Vec::new();
        for i in 0..100 {
            let data = format!("message-{}", i);
            let ct = engine.encrypt("concurrent", data.as_bytes()).await.unwrap();
            ciphertexts.push((data, ct));
        }

        // All should decrypt correctly
        for (original, ct) in ciphertexts {
            let decrypted = engine.decrypt("concurrent", &ct).await.unwrap();
            assert_eq!(String::from_utf8(decrypted).unwrap(), original);
        }
    }
}
