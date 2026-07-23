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
//!
//! ## Encryption scheme
//!
//! Secret data is encrypted with AES-256-GCM under a key derived per
//! `(path, version, generation salt)`: HKDF-SHA256 over the master key with
//! `info = "egide-secrets-v3:{path}:{version}:{generation_salt}"`. The
//! generation salt is a random value drawn once when a path is first written
//! (version 1) and reused, unchanged, by every later version of that path, so
//! a path that is soft-deleted, purged, and re-created draws a fresh salt and
//! never re-derives the key its previous generation used, even though
//! numbering restarts at version 1. Each version row is inserted exactly
//! once, so at most one ciphertext is ever persisted per derived key; the
//! rare transient encryptions under a reused derivation context (CAS races)
//! stay far below the NIST SP 800-38D bound on random 96-bit nonces (2^32
//! messages per key), regardless of rotation rate.
//!
//! Rows written before the generation salt existed carry no salt: they keep
//! deriving under the prior `egide-secrets-v2:{path}:{version}` context
//! instead of `v3`, so they remain readable without a migration pass over
//! existing ciphertext.
//!
//! The AEAD associated data is a canonical length-prefixed encoding of the
//! domain tag, `path`, `version`, and the immutable per-version context columns
//! `expires_at` and `metadata`. It seals each ciphertext to its storage
//! coordinates and to that context: moving or swapping blobs between rows, or
//! tampering with the expiry or metadata columns, fails authentication.
//!
//! Alternatives considered and rejected: XChaCha20-Poly1305 (larger nonce
//! but a new dependency, divergence from the AES-256-GCM doctrine used
//! elsewhere, and no protection against cross-version splicing on its own)
//! and deterministic counter nonces (fragile under concurrency and retries).

#![forbid(unsafe_code)]

pub mod error;

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use tracing::{debug, info, warn};

use egide_crypto::{aead, kdf, mac, random, MasterKey};
use egide_storage::prefix_pattern;
use egide_storage_sqlite::SqliteBackend;

pub use error::SecretsError;

/// Domain separation for secret encryption keys.
///
/// The `v3` bump binds a random per-generation salt into the derivation, so a
/// path that is purged and re-created never re-derives the key it used
/// before. Rows written under `v2` carry no salt and keep their original
/// derivation via [`SECRET_KEY_INFO_PREFIX_V2`].
const SECRET_KEY_INFO_PREFIX: &str = "egide-secrets-v3:";

/// Domain separation for secret encryption keys derived without a generation
/// salt.
///
/// Kept alongside [`SECRET_KEY_INFO_PREFIX`] for as long as rows written
/// under this scheme exist: it is what makes them still readable. The `v2`
/// bump binds the secret version into the derivation, giving one key per
/// `(path, version)` pair. Ciphertexts written under the `v1` scheme
/// (path-only derivation) are deliberately not decryptable.
const SECRET_KEY_INFO_PREFIX_V2: &str = "egide-secrets-v2:";

/// Domain separation for the AEAD associated data.
const SECRET_AAD_PREFIX: &str = "egide-secrets:";

/// Domain separation for the version-pointer row MAC subkey.
const SECRET_POINTER_MAC_INFO: &[u8] = b"egide-secrets-pointer-mac-v1";

/// SQL schema for secrets tables.
const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS secrets (
    path        TEXT PRIMARY KEY,
    version     INTEGER NOT NULL DEFAULT 1,
    deleted_at  INTEGER,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    row_mac     TEXT
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
    generation_salt TEXT,
    PRIMARY KEY (path, version)
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_path ON secret_versions(path);
";

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

/// The Secrets Engine provides secure storage for key-value secrets.
pub struct SecretsEngine {
    storage: SqliteBackend,
    master_key: MasterKey,
}

impl SecretsEngine {
    /// Creates a new `SecretsEngine` with the given storage path and master key.
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

        // Egide has no versioned migration framework: the schema is applied
        // on every boot. SQLite rejects ADD COLUMN IF NOT EXISTS, so the
        // duplicate-column error is the idempotency signal here.
        let add_column = self
            .storage
            .execute(
                "ALTER TABLE secret_versions ADD COLUMN generation_salt TEXT",
                &[],
            )
            .await;

        if let Err(error) = add_column {
            let message = error.to_string();
            if !message.contains("duplicate column") && !message.contains("already exists") {
                return Err(SecretsError::Storage(message));
            }
        }

        Ok(())
    }

    /// Derives an encryption key for one version of a secret.
    ///
    /// Each `(path, version, generation_salt)` triple yields a distinct key,
    /// so every derived key encrypts exactly one message and the
    /// random-nonce birthday bound of AES-GCM can never be approached. When
    /// `generation_salt` is `None`, the key is derived under the legacy `v2`
    /// context so rows written before the salt existed stay readable.
    ///
    /// `generation_salt` is the hex-encoded string as stored in the
    /// `generation_salt` column, not raw bytes: that stored form is what
    /// enters the HKDF info string.
    fn derive_secret_key(
        &self,
        path: &str,
        version: u32,
        generation_salt: Option<&str>,
    ) -> Result<egide_crypto::SymmetricKey, SecretsError> {
        let info = match generation_salt {
            Some(salt) => format!("{SECRET_KEY_INFO_PREFIX}{path}:{version}:{salt}"),
            None => format!("{SECRET_KEY_INFO_PREFIX_V2}{path}:{version}"),
        };
        let key_bytes = kdf::derive_key(self.master_key.as_bytes(), None, info.as_bytes(), 32)?;
        egide_crypto::SymmetricKey::from_bytes(&key_bytes).map_err(SecretsError::from)
    }

    /// Builds the AEAD associated data sealing a ciphertext to its row.
    ///
    /// Binds the storage coordinates (`path`, `version`) and the immutable
    /// per-version context columns (`expires_at`, `metadata`) using a canonical
    /// length-prefixed encoding. The exact stored string forms are bound, so a
    /// tamper of either column makes decryption fail closed.
    fn secret_aad(
        path: &str,
        version: u32,
        expires_at_repr: &str,
        metadata_repr: &str,
    ) -> Result<Vec<u8>, SecretsError> {
        mac::encode_fields(&[
            SECRET_AAD_PREFIX.as_bytes(),
            path.as_bytes(),
            &version.to_be_bytes(),
            expires_at_repr.as_bytes(),
            metadata_repr.as_bytes(),
        ])
        .map_err(SecretsError::from)
    }

    /// Computes the hex-encoded keyed MAC authenticating the version pointer.
    ///
    /// Binds `(path, version, deleted_at)` under a subkey derived from the
    /// master key, so a storage-level rollback of the pointer or a flip of the
    /// soft-delete flag is detected on read.
    fn pointer_mac(
        &self,
        path: &str,
        version: u32,
        deleted_at_repr: &str,
    ) -> Result<String, SecretsError> {
        let subkey =
            kdf::derive_encryption_key(self.master_key.as_bytes(), SECRET_POINTER_MAC_INFO)?;
        let data = mac::encode_fields(&[
            path.as_bytes(),
            &version.to_be_bytes(),
            deleted_at_repr.as_bytes(),
        ])
        .map_err(SecretsError::from)?;
        let tag = mac::compute_mac(&subkey[..], &data).map_err(SecretsError::from)?;
        Ok(hex_encode(&tag))
    }

    /// Verifies the stored version-pointer MAC, failing closed on any anomaly.
    ///
    /// Recomputes the keyed MAC over `(path, version, deleted_at_repr)` with the
    /// same subkey as [`Self::pointer_mac`] and compares it, in constant time,
    /// against the hex tag read from the `row_mac` column. The parameters are
    /// authenticated inputs, not query fragments: they are fed into the injective
    /// field encoding and the HMAC, never into any SQL statement.
    ///
    /// # Errors
    ///
    /// Returns [`SecretsError::Integrity`] if the stored tag is not valid hex or
    /// does not match the recomputed MAC (a tampered, regressed, or absent
    /// pointer), and propagates [`SecretsError::Crypto`] if subkey derivation or
    /// the MAC computation itself fails. Callers must treat any error as a
    /// refusal to trust the pointer.
    fn verify_pointer_mac(
        &self,
        path: &str,
        version: u32,
        deleted_at_repr: &str,
        stored_hex: &str,
    ) -> Result<(), SecretsError> {
        let subkey =
            kdf::derive_encryption_key(self.master_key.as_bytes(), SECRET_POINTER_MAC_INFO)?;
        let data = mac::encode_fields(&[
            path.as_bytes(),
            &version.to_be_bytes(),
            deleted_at_repr.as_bytes(),
        ])
        .map_err(SecretsError::from)?;
        let stored = hex_decode(stored_hex)
            .map_err(|e| SecretsError::Integrity(format!("invalid pointer mac encoding: {e}")))?;
        mac::verify_mac(&subkey[..], &data, &stored)
            .map_err(|_| SecretsError::Integrity(format!("pointer mac mismatch for {path}")))
    }

    /// Encrypts secret data for storage.
    fn encrypt_data(
        &self,
        path: &str,
        version: u32,
        generation_salt: Option<&str>,
        expires_at_repr: &str,
        metadata_repr: &str,
        data: &HashMap<String, String>,
    ) -> Result<(Vec<u8>, Vec<u8>), SecretsError> {
        let key = self.derive_secret_key(path, version, generation_salt)?;
        let plaintext = serde_json::to_vec(data)
            .map_err(|e| SecretsError::Crypto(format!("serialization failed: {e}")))?;

        let aad = Self::secret_aad(path, version, expires_at_repr, metadata_repr)?;
        let ciphertext = aead::encrypt(key.as_bytes(), &plaintext, Some(&aad))?;

        // Extract nonce from ciphertext (first 12 bytes in our format)
        let nonce = ciphertext[..12].to_vec();
        let data = ciphertext[12..].to_vec();

        Ok((data, nonce))
    }

    /// Decrypts secret data from storage.
    ///
    /// `sealed` is the stored `(data, nonce)` pair, grouped into a single
    /// parameter to keep the argument count within the workspace clippy
    /// limit.
    fn decrypt_data(
        &self,
        path: &str,
        version: u32,
        generation_salt: Option<&str>,
        expires_at_repr: &str,
        metadata_repr: &str,
        sealed: (&[u8], &[u8]),
    ) -> Result<HashMap<String, String>, SecretsError> {
        let (data, nonce) = sealed;
        let key = self.derive_secret_key(path, version, generation_salt)?;

        // Reconstruct ciphertext with nonce prefix
        let mut ciphertext = Vec::with_capacity(nonce.len() + data.len());
        ciphertext.extend_from_slice(nonce);
        ciphertext.extend_from_slice(data);

        let aad = Self::secret_aad(path, version, expires_at_repr, metadata_repr)?;
        let plaintext = aead::decrypt(key.as_bytes(), &ciphertext, Some(&aad))?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| SecretsError::Crypto(format!("deserialization failed: {e}")))
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
            .map_err(|e| SecretsError::Storage(format!("metadata serialization failed: {e}")))?;

        // Check if secret exists
        let existing = self
            .storage
            .query_one::<(i64, Option<i64>, String)>(
                "SELECT version, deleted_at, COALESCE(row_mac, '') FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        let new_version: u32;
        let existing_generation_salt: Option<String>;

        if let Some((current_version, deleted_at, row_mac)) = existing {
            // Secret exists: authenticate the pointer before trusting its version.
            let current_version = u32::try_from(current_version).unwrap_or(0);
            let deleted_at_repr = deleted_at.map(|d| d.to_string()).unwrap_or_default();
            self.verify_pointer_mac(path, current_version, &deleted_at_repr, &row_mac)?;

            if deleted_at.is_some() {
                return Err(SecretsError::Deleted(path.to_string()));
            }

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

            // Read the previous version's generation salt so this new version
            // stays in the same context family instead of starting one of its
            // own.
            existing_generation_salt = self
                .storage
                .query_one::<(String,)>(
                    "SELECT COALESCE(generation_salt, '') FROM secret_versions WHERE path = ? AND version = ?",
                    &[path, &current_version.to_string()],
                )
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?
                .map(|(salt,)| salt)
                .filter(|salt| !salt.is_empty());

            // Update secrets table
            let row_mac = self.pointer_mac(path, new_version, "")?;
            self.storage
                .execute(
                    "UPDATE secrets SET version = ?, updated_at = ?, row_mac = ? WHERE path = ?",
                    &[
                        &i64::from(new_version).to_string(),
                        &now.to_string(),
                        &row_mac,
                        path,
                    ],
                )
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?;
        } else {
            // New secret
            if options.cas.is_some() {
                return Err(SecretsError::NotFound(path.to_string()));
            }

            new_version = 1;
            existing_generation_salt = None;

            // Insert into secrets table
            let row_mac = self.pointer_mac(path, new_version, "")?;
            self.storage
                .execute(
                    "INSERT INTO secrets (path, version, created_at, updated_at, row_mac) VALUES (?, ?, ?, ?, ?)",
                    &[
                        path,
                        &new_version.to_string(),
                        &now.to_string(),
                        &now.to_string(),
                        &row_mac,
                    ],
                )
                .await
                .map_err(|e| SecretsError::Storage(e.to_string()))?;
        }

        // A generation salt is drawn once per generation and reused by every
        // version of that generation, so all versions of a path derive from
        // the same context family while a purged-and-recreated path never
        // does.
        let generation_salt = match existing_generation_salt {
            Some(salt) => salt,
            None => hex_encode(random::generate_key()?.as_ref()),
        };

        // The exact stored string forms of the immutable per-version context,
        // bound into the AAD so a later tamper of either column fails closed.
        let expires_at_repr = expires_at.map(|e| e.to_string()).unwrap_or_default();
        let metadata_repr = metadata_json.unwrap_or_default();

        // Encrypt and store version data
        let (encrypted_data, nonce) = self.encrypt_data(
            path,
            new_version,
            Some(generation_salt.as_str()),
            &expires_at_repr,
            &metadata_repr,
            &data,
        )?;

        self.storage
            .execute(
                "INSERT INTO secret_versions (path, version, data, nonce, expires_at, metadata, created_at, created_by, generation_salt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                &[
                    path,
                    &new_version.to_string(),
                    &hex_encode(&encrypted_data),
                    &hex_encode(&nonce),
                    &expires_at_repr,
                    &metadata_repr,
                    &now.to_string(),
                    &self.storage.current_actor().unwrap_or_default(),
                    &generation_salt,
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
            .query_one::<(i64, Option<i64>, String)>(
                "SELECT version, deleted_at, COALESCE(row_mac, '') FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::NotFound(path.to_string()))?;

        let (version, deleted_at, row_mac) = row;
        let version = u32::try_from(version).unwrap_or(0);
        let deleted_at_repr = deleted_at.map(|d| d.to_string()).unwrap_or_default();
        self.verify_pointer_mac(path, version, &deleted_at_repr, &row_mac)?;

        if deleted_at.is_some() {
            return Err(SecretsError::Deleted(path.to_string()));
        }

        self.get_version(path, version).await
    }

    /// Retrieves a specific version of a secret.
    pub async fn get_version(&self, path: &str, version: u32) -> Result<Secret, SecretsError> {
        Self::validate_path(path)?;

        // Check the version pointer (current version, deleted_at) is intact before trusting it.
        // The pointer MAC authenticates the CURRENT version, independent of the requested
        // `version` argument below, which only selects the blob to fetch; that blob is
        // separately authenticated by its own AEAD/AAD.
        let pointer = self
            .storage
            .query_one::<(i64, Option<i64>, String)>(
                "SELECT version, deleted_at, COALESCE(row_mac, '') FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        match pointer {
            Some((current_version, deleted_at, row_mac)) => {
                let current_version = u32::try_from(current_version).unwrap_or(0);
                let deleted_at_repr = deleted_at.map(|d| d.to_string()).unwrap_or_default();
                self.verify_pointer_mac(path, current_version, &deleted_at_repr, &row_mac)?;
                if deleted_at.is_some() {
                    return Err(SecretsError::Deleted(path.to_string()));
                }
            },
            None => return Err(SecretsError::NotFound(path.to_string())),
        }

        let row = self
            .storage
            .query_one::<(String, String, String, String, String, String)>(
                "SELECT data, nonce, COALESCE(CAST(expires_at AS TEXT), ''), COALESCE(metadata, ''), CAST(created_at AS TEXT), COALESCE(generation_salt, '') FROM secret_versions WHERE path = ? AND version = ?",
                &[path, &version.to_string()],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::VersionNotFound {
                path: path.to_string(),
                version,
            })?;

        let (data_hex, nonce_hex, expires_at_str, metadata_json, created_at_str, salt_repr) = row;
        let generation_salt = if salt_repr.is_empty() {
            None
        } else {
            Some(salt_repr.as_str())
        };

        // Parse timestamps
        let created_at: u64 = created_at_str.parse().unwrap_or(0);
        let expires_at: Option<u64> = if expires_at_str.is_empty() {
            None
        } else {
            Some(expires_at_str.parse().map_err(|_| {
                SecretsError::Integrity(format!("unparsable expires_at for {path} v{version}"))
            })?)
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
            .map_err(|e| SecretsError::Storage(format!("invalid data encoding: {e}")))?;
        let nonce_bytes = hex_decode(&nonce_hex)
            .map_err(|e| SecretsError::Storage(format!("invalid nonce encoding: {e}")))?;

        let data = self.decrypt_data(
            path,
            version,
            generation_salt,
            &expires_at_str,
            &metadata_json,
            (&data_bytes, &nonce_bytes),
        )?;

        let metadata = if metadata_json.is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&metadata_json)
                    .map_err(|e| SecretsError::Storage(format!("invalid metadata: {e}")))?,
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
            .query_one::<(i64, Option<i64>, String)>(
                "SELECT version, deleted_at, COALESCE(row_mac, '') FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::NotFound(path.to_string()))?;

        let (version, deleted_at, stored_mac) = row;
        let version = u32::try_from(version).unwrap_or(0);
        let deleted_at_repr = deleted_at.map(|d| d.to_string()).unwrap_or_default();
        self.verify_pointer_mac(path, version, &deleted_at_repr, &stored_mac)?;
        if deleted_at.is_some() {
            return Err(SecretsError::Deleted(path.to_string()));
        }

        let now = Self::now();
        let row_mac = self.pointer_mac(path, version, &now.to_string())?;
        self.storage
            .execute(
                "UPDATE secrets SET deleted_at = ?, row_mac = ? WHERE path = ?",
                &[&now.to_string(), &row_mac, path],
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
            .query_one::<(i64, Option<i64>, String)>(
                "SELECT version, deleted_at, COALESCE(row_mac, '') FROM secrets WHERE path = ?",
                &[path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?
            .ok_or_else(|| SecretsError::NotFound(path.to_string()))?;

        let (version, deleted_at, stored_mac) = row;
        let version = u32::try_from(version).unwrap_or(0);
        let deleted_at_repr = deleted_at.map(|d| d.to_string()).unwrap_or_default();
        self.verify_pointer_mac(path, version, &deleted_at_repr, &stored_mac)?;
        if deleted_at.is_none() {
            return Err(SecretsError::NotDeleted(path.to_string()));
        }

        let row_mac = self.pointer_mac(path, version, "")?;
        self.storage
            .execute(
                "UPDATE secrets SET deleted_at = NULL, updated_at = ?, row_mac = ? WHERE path = ?",
                &[&Self::now().to_string(), &row_mac, path],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        info!(path = path, "Secret restored");
        Ok(())
    }

    /// Lists secrets matching a prefix.
    pub async fn list(&self, prefix: &str) -> Result<Vec<SecretMetadata>, SecretsError> {
        let pattern = prefix_pattern(prefix);
        let rows = self
            .storage
            .query_all::<(String, String, String, String, String)>(
                "SELECT path, CAST(version AS TEXT), CAST(created_at AS TEXT), CAST(updated_at AS TEXT), COALESCE(CAST(deleted_at AS TEXT), '') FROM secrets WHERE path LIKE ? ESCAPE '\\' ORDER BY path",
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
                        Some(expires_at_str.parse().map_err(|_| {
                            SecretsError::Integrity(format!(
                                "unparsable expires_at in versions list for {path}"
                            ))
                        })?)
                    };
                    let expired = expires_at.is_some_and(|e| e < now);
                    Ok(SecretVersionInfo {
                        version,
                        created_at,
                        expires_at,
                        created_by: if created_by.is_empty() {
                            None
                        } else {
                            Some(created_by)
                        },
                        expired,
                    })
                },
            )
            .collect::<Result<Vec<_>, SecretsError>>()?;

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
        let cutoff = Self::now().saturating_sub(older_than.as_secs());

        // Candidates: soft-deleted secrets older than the cutoff. Fetch the
        // pointer fields so each row's MAC can be verified before the
        // irreversible delete. A forged deleted_at on a live secret carries an
        // invalid MAC and must be skipped, not purged, to prevent data loss.
        let candidates = self
            .storage
            .query_all::<(String, i64, Option<i64>, String)>(
                "SELECT path, version, deleted_at, COALESCE(row_mac, '') FROM secrets WHERE deleted_at IS NOT NULL AND deleted_at < ?",
                &[&cutoff.to_string()],
            )
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;

        let mut count: u32 = 0;
        for (path, version, deleted_at, row_mac) in candidates {
            let version = u32::try_from(version).unwrap_or(0);
            let deleted_at_repr = deleted_at.map(|d| d.to_string()).unwrap_or_default();
            if self
                .verify_pointer_mac(&path, version, &deleted_at_repr, &row_mac)
                .is_err()
            {
                warn!(path = path, "Skipping purge: invalid version-pointer MAC");
                continue;
            }

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

            count = count.saturating_add(1);
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
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("odd length hex string".into());
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| "invalid hex".to_string())?;
            u8::from_str_radix(s, 16).map_err(|e| e.to_string())
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn setup() -> (TempDir, SecretsEngine) {
        let tmp = TempDir::new().unwrap();
        let master_key = MasterKey::generate().unwrap();
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
    async fn test_put_populates_pointer_mac() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/p", test_data(), PutOptions::default())
            .await
            .unwrap();

        let row_mac: (String,) = engine
            .storage
            .query_one::<(String,)>(
                "SELECT COALESCE(row_mac, '') FROM secrets WHERE path = ?",
                &["app/p"],
            )
            .await
            .unwrap()
            .unwrap();
        assert!(!row_mac.0.is_empty(), "row_mac must be populated on put");

        // The stored tag must be the MAC over (path, version=1, deleted_at="").
        let expected = engine.pointer_mac("app/p", 1, "").unwrap();
        assert_eq!(row_mac.0, expected);
    }

    #[tokio::test]
    async fn test_rolled_back_version_pointer_fails() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/roll", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("app/roll", test_data(), PutOptions::default())
            .await
            .unwrap(); // now v2

        // Roll the pointer back to v1 without updating row_mac (storage tamper).
        engine
            .storage
            .execute(
                "UPDATE secrets SET version = ? WHERE path = ?",
                &["1", "app/roll"],
            )
            .await
            .unwrap();

        let result = engine.get("app/roll").await;
        assert!(
            matches!(result, Err(SecretsError::Integrity(_))),
            "rolled-back version pointer must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_flipped_delete_flag_fails() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/flip", test_data(), PutOptions::default())
            .await
            .unwrap();

        // Forge a soft-delete without updating row_mac.
        engine
            .storage
            .execute(
                "UPDATE secrets SET deleted_at = ? WHERE path = ?",
                &["1000", "app/flip"],
            )
            .await
            .unwrap();

        let result = engine.get("app/flip").await;
        assert!(
            matches!(result, Err(SecretsError::Integrity(_))),
            "forged deleted_at must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_purge_skips_forged_delete_flag_on_live_secret() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/live", test_data(), PutOptions::default())
            .await
            .unwrap();

        // Forge a past deleted_at on a LIVE secret (row_mac still authenticates
        // the live state, so this row's MAC is now invalid).
        engine
            .storage
            .execute(
                "UPDATE secrets SET deleted_at = ? WHERE path = ?",
                &["1", "app/live"],
            )
            .await
            .unwrap();

        let purged = engine
            .purge_deleted(std::time::Duration::from_secs(0))
            .await
            .unwrap();
        assert_eq!(
            purged, 0,
            "forged deleted_at on a live secret must not be purged"
        );

        let still_there = engine
            .storage
            .query_one::<(String,)>("SELECT path FROM secrets WHERE path = ?", &["app/live"])
            .await
            .unwrap();
        assert!(
            still_there.is_some(),
            "forged-flag secret row must survive purge"
        );
    }

    #[tokio::test]
    async fn test_put_rejects_rolled_back_pointer() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/pl", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("app/pl", test_data(), PutOptions::default())
            .await
            .unwrap(); // now v2

        // Roll the pointer back to v1 without fixing row_mac.
        engine
            .storage
            .execute(
                "UPDATE secrets SET version = ? WHERE path = ?",
                &["1", "app/pl"],
            )
            .await
            .unwrap();

        let result = engine
            .put("app/pl", test_data(), PutOptions::default())
            .await;
        assert!(
            matches!(result, Err(SecretsError::Integrity(_))),
            "put on a tampered pointer must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_pointer_mac_roundtrips_through_lifecycle() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/life", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("app/life", test_data(), PutOptions::default())
            .await
            .unwrap();
        assert_eq!(engine.get("app/life").await.unwrap().version, 2);
        engine.delete("app/life").await.unwrap();
        assert!(matches!(
            engine.get("app/life").await,
            Err(SecretsError::Deleted(_))
        ));
        engine.undelete("app/life").await.unwrap();
        assert_eq!(engine.get("app/life").await.unwrap().version, 2);
    }

    #[tokio::test]
    async fn test_roundtrip_with_ttl_and_metadata() {
        let (_tmp, engine) = setup().await;
        let opts = PutOptions {
            ttl: Some(std::time::Duration::from_hours(1)),
            metadata: Some(serde_json::json!({"env": "prod"})),
            cas: None,
        };
        engine.put("app/full", test_data(), opts).await.unwrap();

        let secret = engine.get_version("app/full", 1).await.unwrap();
        assert_eq!(secret.data, test_data());
        assert!(secret.expires_at.is_some());
        assert_eq!(secret.metadata, Some(serde_json::json!({"env": "prod"})));
    }

    #[tokio::test]
    async fn test_roundtrip_without_ttl_or_metadata() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/bare", test_data(), PutOptions::default())
            .await
            .unwrap();
        let secret = engine.get_version("app/bare", 1).await.unwrap();
        assert_eq!(secret.data, test_data());
    }

    #[tokio::test]
    async fn test_tampered_metadata_fails_decryption() {
        let (_tmp, engine) = setup().await;
        let opts = PutOptions {
            ttl: None,
            metadata: Some(serde_json::json!({"role": "admin"})),
            cas: None,
        };
        engine.put("app/meta", test_data(), opts).await.unwrap();

        // Substitute metadata with valid JSON that parses but was not authenticated.
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET metadata = ? WHERE path = ? AND version = 1",
                &[r#"{"role":"guest"}"#, "app/meta"],
            )
            .await
            .unwrap();

        let result = engine.get_version("app/meta", 1).await;
        assert!(
            result.is_err(),
            "tampered metadata must never decrypt or return the secret"
        );
    }

    #[tokio::test]
    async fn test_tampered_expires_at_fails_decryption() {
        let (_tmp, engine) = setup().await;
        let opts = PutOptions {
            ttl: Some(std::time::Duration::from_hours(1)),
            metadata: None,
            cas: None,
        };
        engine.put("app/exp", test_data(), opts).await.unwrap();

        // Extend the TTL to a far future value that parses fine but was not authenticated.
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET expires_at = ? WHERE path = ? AND version = 1",
                &["9999999999", "app/exp"],
            )
            .await
            .unwrap();

        let result = engine.get_version("app/exp", 1).await;
        assert!(result.is_err(), "tampered expires_at must not decrypt");
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
    async fn test_get_version_respects_soft_delete() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/deleted", test_data(), PutOptions::default())
            .await
            .unwrap();

        // Soft delete
        engine.delete("app/deleted").await.unwrap();

        // get_version should also return Deleted error (regression test)
        let result = engine.get_version("app/deleted", 1).await;
        assert!(matches!(result, Err(SecretsError::Deleted(_))));

        // After undelete, get_version should work
        engine.undelete("app/deleted").await.unwrap();
        let secret = engine.get_version("app/deleted", 1).await.unwrap();
        assert_eq!(secret.version, 1);
    }

    #[tokio::test]
    async fn test_purge_deleted_does_not_purge_when_older_than_exceeds_now() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/retained", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine.delete("app/retained").await.unwrap();

        // A retention duration longer than the current Unix time must not
        // underflow the cutoff computation, and must not purge anything.
        let purged = engine
            .purge_deleted(Duration::from_secs(u64::MAX))
            .await
            .unwrap();

        assert_eq!(purged, 0);

        // The secret must still be recoverable.
        engine.undelete("app/retained").await.unwrap();
        let secret = engine.get("app/retained").await.unwrap();
        assert_eq!(secret.data.get("username").unwrap(), "admin");
    }

    #[tokio::test]
    async fn test_purge_deleted_purges_old_soft_deleted_secrets() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/stale", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine.delete("app/stale").await.unwrap();

        // Ensure deleted_at lands strictly before the purge cutoff.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let purged = engine.purge_deleted(Duration::from_secs(0)).await.unwrap();
        assert_eq!(purged, 1);

        let result = engine.get("app/stale").await;
        assert!(matches!(result, Err(SecretsError::NotFound(_))));
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
    async fn test_list_does_not_treat_underscore_as_a_wildcard() {
        let (_tmp, engine) = setup().await;

        engine
            .put("prod_db/password", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("prodXdb/password", test_data(), PutOptions::default())
            .await
            .unwrap();

        let list = engine.list("prod_db/").await.unwrap();

        assert_eq!(
            list.len(),
            1,
            "an underscore in the prefix must match literally"
        );
        assert_eq!(list[0].path, "prod_db/password");
    }

    #[tokio::test]
    async fn test_list_does_not_treat_percent_as_a_wildcard() {
        let (_tmp, engine) = setup().await;

        engine
            .put("prod/db", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .put("prodextra/db", test_data(), PutOptions::default())
            .await
            .unwrap();

        let list = engine.list("prod%").await.unwrap();

        assert!(
            list.is_empty(),
            "a percent sign in the prefix must match literally"
        );
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

        let key1 = MasterKey::generate().unwrap();
        let key2 = MasterKey::generate().unwrap();

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
            // The pointer MAC is keyed by the master key too, so a wrong key fails
            // pointer verification before content decryption is ever attempted.
            assert!(matches!(result, Err(SecretsError::Integrity(_))));
        }

        // Engine 1 with same key can read
        {
            let engine1 = SecretsEngine::new(tmp.path(), "test", key1).await.unwrap();
            let secret = engine1.get("shared/path").await.unwrap();
            assert_eq!(secret.data.get("username").unwrap(), "admin");
        }
    }

    #[tokio::test]
    async fn test_swapped_version_blobs_fail_decryption() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/spliced", test_data(), PutOptions::default())
            .await
            .unwrap();
        let mut data2 = test_data();
        data2.insert("password".to_string(), "rotated".to_string());
        engine
            .put("app/spliced", data2, PutOptions::default())
            .await
            .unwrap();

        let (data_v1, nonce_v1) = engine
            .storage
            .query_one::<(String, String)>(
                "SELECT data, nonce FROM secret_versions WHERE path = ? AND version = 1",
                &["app/spliced"],
            )
            .await
            .unwrap()
            .unwrap();
        let (data_v2, nonce_v2) = engine
            .storage
            .query_one::<(String, String)>(
                "SELECT data, nonce FROM secret_versions WHERE path = ? AND version = 2",
                &["app/spliced"],
            )
            .await
            .unwrap()
            .unwrap();

        // Swap the encrypted blobs underneath the engine, simulating an
        // attacker with direct storage access.
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET data = ?, nonce = ? WHERE path = ? AND version = 1",
                &[&data_v2, &nonce_v2, "app/spliced"],
            )
            .await
            .unwrap();
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET data = ?, nonce = ? WHERE path = ? AND version = 2",
                &[&data_v1, &nonce_v1, "app/spliced"],
            )
            .await
            .unwrap();

        let result_v1 = engine.get_version("app/spliced", 1).await;
        assert!(matches!(result_v1, Err(SecretsError::Crypto(_))));
        let result_v2 = engine.get_version("app/spliced", 2).await;
        assert!(matches!(result_v2, Err(SecretsError::Crypto(_))));
    }

    #[tokio::test]
    async fn test_get_version_rejects_unparsable_expires_at() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/ttl", test_data(), PutOptions::default())
            .await
            .unwrap();

        // Corrupt expires_at to a non-numeric value in storage.
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET expires_at = ? WHERE path = ? AND version = 1",
                &["not-a-number", "app/ttl"],
            )
            .await
            .unwrap();

        let result = engine.get_version("app/ttl", 1).await;
        assert!(
            matches!(result, Err(SecretsError::Integrity(_))),
            "unparsable expires_at must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_versions_rejects_unparsable_expires_at() {
        let (_tmp, engine) = setup().await;
        engine
            .put("app/ttl", test_data(), PutOptions::default())
            .await
            .unwrap();
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET expires_at = ? WHERE path = ? AND version = 1",
                &["not-a-number", "app/ttl"],
            )
            .await
            .unwrap();

        let result = engine.versions("app/ttl").await;
        assert!(
            matches!(result, Err(SecretsError::Integrity(_))),
            "unparsable expires_at must fail closed in versions list, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_replayed_blob_under_other_version_fails() {
        let (_tmp, engine) = setup().await;

        engine
            .put("app/replayed", test_data(), PutOptions::default())
            .await
            .unwrap();
        let mut data2 = test_data();
        data2.insert("password".to_string(), "rotated".to_string());
        engine
            .put("app/replayed", data2, PutOptions::default())
            .await
            .unwrap();

        let (data_v1, nonce_v1) = engine
            .storage
            .query_one::<(String, String)>(
                "SELECT data, nonce FROM secret_versions WHERE path = ? AND version = 1",
                &["app/replayed"],
            )
            .await
            .unwrap()
            .unwrap();

        // Replay version 1's blob in version 2's row: a rollback forged at
        // the storage layer must not authenticate.
        engine
            .storage
            .execute(
                "UPDATE secret_versions SET data = ?, nonce = ? WHERE path = ? AND version = 2",
                &[&data_v1, &nonce_v1, "app/replayed"],
            )
            .await
            .unwrap();

        let result = engine.get_version("app/replayed", 2).await;
        assert!(matches!(result, Err(SecretsError::Crypto(_))));
    }

    #[tokio::test]
    async fn test_derived_keys_differ_across_versions_and_paths() {
        let (_tmp, engine) = setup().await;

        let key_v1 = engine.derive_secret_key("app/kdf", 1, None).unwrap();
        let key_v2 = engine.derive_secret_key("app/kdf", 2, None).unwrap();
        let key_other_path = engine.derive_secret_key("app/kdf-other", 1, None).unwrap();

        assert_ne!(key_v1.as_bytes(), key_v2.as_bytes());
        assert_ne!(key_v1.as_bytes(), key_other_path.as_bytes());
        assert_ne!(key_v2.as_bytes(), key_other_path.as_bytes());
    }

    #[tokio::test]
    async fn test_derivation_differs_across_generation_salts() {
        let (_tmp, engine) = setup().await;

        let without = engine.derive_secret_key("app/gen", 1, None).unwrap();
        let with_first = engine
            .derive_secret_key("app/gen", 1, Some("00112233445566778899aabbccddeeff"))
            .unwrap();
        let with_second = engine
            .derive_secret_key("app/gen", 1, Some("ffeeddccbbaa99887766554433221100"))
            .unwrap();

        assert_ne!(without.as_bytes(), with_first.as_bytes());
        assert_ne!(with_first.as_bytes(), with_second.as_bytes());
    }

    #[tokio::test]
    async fn test_purge_then_recreate_does_not_reuse_the_derivation_context() {
        let (_tmp, engine) = setup().await;

        let mut data = HashMap::new();
        data.insert("k".to_string(), "first".to_string());
        engine
            .put("app/cycle", data.clone(), PutOptions::default())
            .await
            .unwrap();

        let first_salt = engine
            .storage
            .query_one::<(String,)>(
                "SELECT COALESCE(generation_salt, '') FROM secret_versions WHERE path = ? AND version = 1",
                &["app/cycle"],
            )
            .await
            .unwrap()
            .unwrap()
            .0;

        engine.delete("app/cycle").await.unwrap();

        // Ensure deleted_at lands strictly before the purge cutoff.
        tokio::time::sleep(Duration::from_secs(2)).await;

        engine.purge_deleted(Duration::from_secs(0)).await.unwrap();

        data.insert("k".to_string(), "second".to_string());
        engine
            .put("app/cycle", data, PutOptions::default())
            .await
            .unwrap();

        let second_salt = engine
            .storage
            .query_one::<(String,)>(
                "SELECT COALESCE(generation_salt, '') FROM secret_versions WHERE path = ? AND version = 1",
                &["app/cycle"],
            )
            .await
            .unwrap()
            .unwrap()
            .0;

        assert!(
            !first_salt.is_empty(),
            "a fresh generation must carry a salt"
        );
        assert_ne!(
            first_salt, second_salt,
            "a re-created secret must not reuse the previous derivation context"
        );
    }

    #[tokio::test]
    async fn test_rows_without_a_salt_stay_readable() {
        let (_tmp, engine) = setup().await;

        let mut data = HashMap::new();
        data.insert("k".to_string(), "legacy".to_string());
        engine
            .put("app/legacy", data, PutOptions::default())
            .await
            .unwrap();

        // Simulate a row written before the salt existed: clear the column and
        // re-encrypt under the v2 context.
        let key = engine.derive_secret_key("app/legacy", 1, None).unwrap();
        let mut legacy = HashMap::new();
        legacy.insert("k".to_string(), "legacy".to_string());
        let plaintext = serde_json::to_vec(&legacy).unwrap();
        let aad = SecretsEngine::secret_aad("app/legacy", 1, "", "").unwrap();
        let sealed = aead::encrypt(key.as_bytes(), &plaintext, Some(&aad)).unwrap();
        let nonce_hex = hex_encode(&sealed[..12]);
        let data_hex = hex_encode(&sealed[12..]);

        engine
            .storage
            .execute(
                "UPDATE secret_versions SET generation_salt = NULL, data = ?, nonce = ? WHERE path = ? AND version = 1",
                &[&data_hex, &nonce_hex, "app/legacy"],
            )
            .await
            .unwrap();

        let secret = engine.get("app/legacy").await.unwrap();
        assert_eq!(secret.data.get("k"), Some(&"legacy".to_string()));
    }

    #[tokio::test]
    async fn test_many_rotations_all_versions_decrypt() {
        let (_tmp, engine) = setup().await;

        for i in 1..=50u32 {
            let mut data = HashMap::new();
            data.insert("counter".to_string(), i.to_string());
            engine
                .put("app/rotated", data, PutOptions::default())
                .await
                .unwrap();
        }

        for i in 1..=50u32 {
            let secret = engine.get_version("app/rotated", i).await.unwrap();
            assert_eq!(secret.data.get("counter").unwrap(), &i.to_string());
        }
    }

    #[test]
    fn hex_decode_rejects_non_ascii_input_without_panicking() {
        // A multi-byte UTF-8 char would make a byte-index slice fall inside a code point.
        // Using a 4-byte UTF-8 character (U+10340) to ensure the slice at [0..2] is incomplete.
        assert!(hex_decode("𐍀").is_err());
        assert!(hex_decode("𐍀𐍀").is_err());
    }

    #[tokio::test]
    async fn test_generation_salt_column_is_added_idempotently() {
        let (_tmp, engine) = setup().await;

        // Running the schema routine twice must not fail: there is no
        // versioned migration framework, the schema is applied on every boot.
        engine.init_schema().await.unwrap();
        engine.init_schema().await.unwrap();

        let row = engine
            .storage
            .query_one::<(String,)>(
                "SELECT COALESCE(generation_salt, '') FROM secret_versions LIMIT 1",
                &[],
            )
            .await;

        assert!(
            row.is_ok(),
            "the generation_salt column must exist after initialization"
        );
    }

    #[tokio::test]
    async fn test_generation_salt_column_is_added_to_pre_existing_table() {
        let tmp = TempDir::new().unwrap();
        let storage = SqliteBackend::open(tmp.path(), "test").await.unwrap();

        // Recreate the table shape written before the generation_salt
        // migration existed, so init_schema must migrate it via ALTER TABLE
        // rather than via CREATE TABLE IF NOT EXISTS.
        storage
            .execute_raw(
                r"
                CREATE TABLE secret_versions (
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
                ",
            )
            .await
            .unwrap();

        // The column must be absent before migration, otherwise this test
        // would not distinguish the migration succeeding from it being a
        // silently swallowed no-op.
        let before = storage
            .query_one::<(String,)>(
                "SELECT COALESCE(generation_salt, '') FROM secret_versions LIMIT 1",
                &[],
            )
            .await;
        assert!(
            before.is_err(),
            "generation_salt must be absent before init_schema runs, got {before:?}"
        );

        let master_key = MasterKey::generate().unwrap();
        let engine = SecretsEngine {
            storage,
            master_key,
        };

        engine.init_schema().await.unwrap();

        let after = engine
            .storage
            .query_one::<(String,)>(
                "SELECT COALESCE(generation_salt, '') FROM secret_versions LIMIT 1",
                &[],
            )
            .await;
        assert!(
            after.is_ok(),
            "generation_salt must exist after migrating a pre-existing table, got {after:?}"
        );
    }
}
