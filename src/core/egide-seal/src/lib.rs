//! # Egide Seal
//!
//! Seal/Unseal mechanism for the Egide vault.
//!
//! The vault has two states:
//! - **Sealed**: Master key is not in memory, secrets are inaccessible
//! - **Unsealed**: Master key is in memory, secrets can be accessed
//!
//! ## Shamir's Secret Sharing
//!
//! The master key is split into N shares using Shamir's Secret Sharing.
//! A minimum of M shares (threshold) are required to reconstruct the key.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use sharks::{Share as SharkShare, Sharks};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use egide_crypto::MasterKey;
use egide_storage::StorageBackend;
use egide_storage_sqlite::SqliteBackend;

pub use error::SealError;

/// Keys for system.db storage.
mod keys {
    pub const ROOT_TOKEN_HASH: &str = "root_token_hash";
    pub const SHAMIR_THRESHOLD: &str = "shamir_threshold";
    pub const SHAMIR_TOTAL: &str = "shamir_total";
    pub const INITIALIZED_AT: &str = "initialized_at";
    pub const DEV_MODE_KEY: &str = "dev_mode_master_key";
}

/// State of the vault seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStatus {
    /// Vault has not been initialized yet.
    Uninitialized,
    /// Vault is initialized but sealed.
    Sealed,
    /// Vault is unsealed and operational.
    Unsealed,
}

/// Configuration for Shamir's Secret Sharing.
#[derive(Debug, Clone)]
pub struct ShamirConfig {
    /// Total number of shares to generate (N).
    pub shares: u8,
    /// Minimum shares required to unseal (M).
    pub threshold: u8,
}

impl ShamirConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), SealError> {
        if self.threshold == 0 {
            return Err(SealError::InvalidConfig("threshold must be > 0".into()));
        }
        if self.shares < self.threshold {
            return Err(SealError::InvalidConfig(
                "shares must be >= threshold".into(),
            ));
        }
        Ok(())
    }
}

/// A single Shamir share (given to a key holder).
#[derive(Debug, Clone)]
pub struct Share {
    /// Share index (1-based).
    pub index: u8,
    /// Share data (encoded).
    pub data: Vec<u8>,
}

impl Share {
    /// Encodes the share as a hex string for display.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.data)
    }

    /// Decodes a share from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, SealError> {
        let data = hex_decode(hex).map_err(|e| SealError::InvalidShare(e.to_string()))?;
        if data.is_empty() {
            return Err(SealError::InvalidShare("empty share".into()));
        }
        // First byte is the index in sharks format
        Ok(Self {
            index: data[0],
            data,
        })
    }
}

/// Result of vault initialization.
pub struct InitResult {
    /// Root token (shown only once).
    pub root_token: String,
    /// Shamir shares for key holders.
    pub shares: Vec<Share>,
}

/// Progress of an unseal operation.
#[derive(Debug, Clone)]
pub struct UnsealProgress {
    /// Whether the vault is still sealed.
    pub sealed: bool,
    /// Threshold required to unseal.
    pub threshold: u8,
    /// Number of shares submitted so far.
    pub progress: u8,
}

/// The Seal Manager handles vault locking/unlocking.
pub struct SealManager {
    storage: SqliteBackend,
    #[allow(dead_code)]
    data_path: PathBuf,
    status: SealStatus,
    master_key: Option<MasterKey>,
    pending_shares: Vec<SharkShare>,
    pending_indices: HashSet<u8>,
    threshold: u8,
    dev_mode: bool,
}

impl SealManager {
    /// Creates a new SealManager with storage path.
    pub async fn new(data_path: impl AsRef<Path>) -> Result<Self, SealError> {
        let data_path = data_path.as_ref().to_path_buf();
        let storage = SqliteBackend::open(&data_path, "system").await?;

        let mut manager = Self {
            storage,
            data_path,
            status: SealStatus::Uninitialized,
            master_key: None,
            pending_shares: Vec::new(),
            pending_indices: HashSet::new(),
            threshold: 0,
            dev_mode: false,
        };

        manager.load_status().await?;

        Ok(manager)
    }

    /// Loads the seal status from storage.
    async fn load_status(&mut self) -> Result<(), SealError> {
        let initialized = self.storage.get(keys::INITIALIZED_AT).await?.is_some();

        if initialized {
            self.status = SealStatus::Sealed;

            if let Some(threshold_bytes) = self.storage.get(keys::SHAMIR_THRESHOLD).await? {
                self.threshold = threshold_bytes[0];
            }

            // Check for dev mode
            if let Some(key_bytes) = self.storage.get(keys::DEV_MODE_KEY).await? {
                warn!("⚠️  DEV MODE DETECTED - AUTO-UNSEALING - NOT FOR PRODUCTION ⚠️");
                self.master_key = Some(
                    MasterKey::from_bytes(&key_bytes)
                        .map_err(|e| SealError::Crypto(e.to_string()))?,
                );
                self.status = SealStatus::Unsealed;
                self.dev_mode = true;
            }
        }

        debug!(status = ?self.status, "Seal status loaded");
        Ok(())
    }

    /// Returns the current seal status.
    pub fn status(&self) -> SealStatus {
        self.status
    }

    /// Returns true if running in dev mode.
    pub fn is_dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// Initializes the vault (first time setup).
    pub async fn initialize(&mut self, config: ShamirConfig) -> Result<InitResult, SealError> {
        if self.status != SealStatus::Uninitialized {
            return Err(SealError::AlreadyInitialized);
        }

        config.validate()?;

        info!(
            shares = config.shares,
            threshold = config.threshold,
            "Initializing vault"
        );

        // Generate master key
        let master_key = MasterKey::generate();

        // Split with Shamir
        let sharks = Sharks(config.threshold);
        let dealer = sharks.dealer(master_key.as_bytes());
        let shark_shares: Vec<SharkShare> = dealer.take(config.shares as usize).collect();

        let shares: Vec<Share> = shark_shares
            .iter()
            .map(|s| {
                let bytes: Vec<u8> = s.into();
                Share {
                    index: bytes[0],
                    data: bytes,
                }
            })
            .collect();

        // Generate root token
        let root_token = generate_token(32);
        let root_token_hash = hash_token(&root_token)?;

        // Store configuration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        self.storage
            .put(keys::ROOT_TOKEN_HASH, root_token_hash.as_bytes())
            .await?;
        self.storage
            .put(keys::SHAMIR_THRESHOLD, &[config.threshold])
            .await?;
        self.storage
            .put(keys::SHAMIR_TOTAL, &[config.shares])
            .await?;
        self.storage
            .put(keys::INITIALIZED_AT, &now.to_le_bytes())
            .await?;

        self.status = SealStatus::Sealed;
        self.threshold = config.threshold;

        info!("Vault initialized successfully");

        Ok(InitResult { root_token, shares })
    }

    /// Submits a share for unsealing.
    pub async fn unseal(&mut self, share: &Share) -> Result<UnsealProgress, SealError> {
        match self.status {
            SealStatus::Uninitialized => return Err(SealError::NotInitialized),
            SealStatus::Unsealed => return Err(SealError::AlreadyUnsealed),
            SealStatus::Sealed => {},
        }

        // Check for duplicate
        if self.pending_indices.contains(&share.index) {
            return Err(SealError::DuplicateShare(share.index));
        }

        // Parse share
        let shark_share = SharkShare::try_from(share.data.as_slice())
            .map_err(|_| SealError::InvalidShare("malformed share data".into()))?;

        self.pending_shares.push(shark_share);
        self.pending_indices.insert(share.index);

        debug!(
            index = share.index,
            progress = self.pending_shares.len(),
            threshold = self.threshold,
            "Share submitted"
        );

        // Check if we have enough shares
        if self.pending_shares.len() >= self.threshold as usize {
            self.reconstruct_master_key()?;
        }

        Ok(UnsealProgress {
            sealed: self.status == SealStatus::Sealed,
            threshold: self.threshold,
            progress: self.pending_shares.len() as u8,
        })
    }

    /// Reconstructs the master key from pending shares.
    fn reconstruct_master_key(&mut self) -> Result<(), SealError> {
        let sharks = Sharks(self.threshold);

        let secret = sharks
            .recover(&self.pending_shares)
            .map_err(|_| SealError::ReconstructionFailed)?;

        let master_key =
            MasterKey::from_bytes(&secret).map_err(|e| SealError::Crypto(e.to_string()))?;

        // Clear pending shares (zeroize)
        self.pending_shares.clear();
        self.pending_indices.clear();

        self.master_key = Some(master_key);
        self.status = SealStatus::Unsealed;

        info!("Vault unsealed successfully");

        Ok(())
    }

    /// Seals the vault (clears master key from memory).
    pub fn seal(&mut self) {
        if self.dev_mode {
            warn!("Cannot seal in dev mode");
            return;
        }

        self.master_key = None;
        self.pending_shares.clear();
        self.pending_indices.clear();
        self.status = SealStatus::Sealed;

        info!("Vault sealed");
    }

    /// Returns the master key (only if unsealed).
    pub fn master_key(&self) -> Option<&MasterKey> {
        self.master_key.as_ref()
    }

    /// Enables dev mode (auto-unseal).
    /// WARNING: Never use in production!
    pub async fn enable_dev_mode(&mut self) -> Result<(), SealError> {
        if self.status != SealStatus::Uninitialized {
            return Err(SealError::AlreadyInitialized);
        }

        warn!("⚠️  ENABLING DEV MODE - NOT FOR PRODUCTION ⚠️");

        // Generate and store master key in plaintext
        let master_key = MasterKey::generate();

        // Generate root token
        let root_token = generate_token(32);
        let root_token_hash = hash_token(&root_token)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        self.storage
            .put(keys::ROOT_TOKEN_HASH, root_token_hash.as_bytes())
            .await?;
        self.storage
            .put(keys::DEV_MODE_KEY, master_key.as_bytes())
            .await?;
        self.storage.put(keys::SHAMIR_THRESHOLD, &[1]).await?;
        self.storage.put(keys::SHAMIR_TOTAL, &[1]).await?;
        self.storage
            .put(keys::INITIALIZED_AT, &now.to_le_bytes())
            .await?;

        self.master_key = Some(master_key);
        self.status = SealStatus::Unsealed;
        self.dev_mode = true;
        self.threshold = 1;

        warn!("Dev mode enabled - root token: {}", root_token);

        Ok(())
    }

    /// Verifies a root token.
    pub async fn verify_root_token(&self, token: &str) -> Result<bool, SealError> {
        let stored_hash = self
            .storage
            .get(keys::ROOT_TOKEN_HASH)
            .await?
            .ok_or(SealError::NotInitialized)?;

        let hash_str =
            std::str::from_utf8(&stored_hash).map_err(|e| SealError::Storage(e.to_string()))?;

        Ok(verify_token(token, hash_str))
    }
}

/// Generates a random token as hex string.
fn generate_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex_encode(&buf)
}

/// Hashes a token with Argon2id.
fn hash_token(token: &str) -> Result<String, SealError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| SealError::Crypto(e.to_string()))?;
    Ok(hash.to_string())
}

/// Verifies a token against an Argon2id hash.
fn verify_token(token: &str, hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok()
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

    async fn setup() -> (TempDir, SealManager) {
        let tmp = TempDir::new().unwrap();
        let manager = SealManager::new(tmp.path()).await.unwrap();
        (tmp, manager)
    }

    #[tokio::test]
    async fn test_initial_status_uninitialized() {
        let (_tmp, manager) = setup().await;
        assert_eq!(manager.status(), SealStatus::Uninitialized);
    }

    #[tokio::test]
    async fn test_initialize() {
        let (_tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 5,
            threshold: 3,
        };

        let result = manager.initialize(config).await.unwrap();

        assert_eq!(result.shares.len(), 5);
        assert!(!result.root_token.is_empty());
        assert_eq!(manager.status(), SealStatus::Sealed);
    }

    #[tokio::test]
    async fn test_initialize_twice_fails() {
        let (_tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 3,
            threshold: 2,
        };

        manager.initialize(config.clone()).await.unwrap();
        let result = manager.initialize(config).await;

        assert!(matches!(result, Err(SealError::AlreadyInitialized)));
    }

    #[tokio::test]
    async fn test_unseal_with_threshold_shares() {
        let (_tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 5,
            threshold: 3,
        };

        let init_result = manager.initialize(config).await.unwrap();

        // Submit 3 shares (threshold)
        for i in 0..3 {
            let progress = manager.unseal(&init_result.shares[i]).await.unwrap();

            if i < 2 {
                assert!(progress.sealed);
                assert_eq!(progress.progress, (i + 1) as u8);
            } else {
                assert!(!progress.sealed);
            }
        }

        assert_eq!(manager.status(), SealStatus::Unsealed);
        assert!(manager.master_key().is_some());
    }

    #[tokio::test]
    async fn test_unseal_duplicate_share_fails() {
        let (_tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 3,
            threshold: 2,
        };

        let init_result = manager.initialize(config).await.unwrap();

        manager.unseal(&init_result.shares[0]).await.unwrap();
        let result = manager.unseal(&init_result.shares[0]).await;

        assert!(matches!(result, Err(SealError::DuplicateShare(_))));
    }

    #[tokio::test]
    async fn test_seal_clears_master_key() {
        let (_tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 3,
            threshold: 2,
        };

        let init_result = manager.initialize(config).await.unwrap();

        manager.unseal(&init_result.shares[0]).await.unwrap();
        manager.unseal(&init_result.shares[1]).await.unwrap();

        assert!(manager.master_key().is_some());

        manager.seal();

        assert!(manager.master_key().is_none());
        assert_eq!(manager.status(), SealStatus::Sealed);
    }

    #[tokio::test]
    async fn test_dev_mode() {
        let (_tmp, mut manager) = setup().await;

        manager.enable_dev_mode().await.unwrap();

        assert_eq!(manager.status(), SealStatus::Unsealed);
        assert!(manager.is_dev_mode());
        assert!(manager.master_key().is_some());
    }

    #[tokio::test]
    async fn test_dev_mode_auto_unseal_on_restart() {
        let tmp = TempDir::new().unwrap();

        // First instance - enable dev mode
        {
            let mut manager = SealManager::new(tmp.path()).await.unwrap();
            manager.enable_dev_mode().await.unwrap();
        }

        // Second instance - should auto-unseal
        {
            let manager = SealManager::new(tmp.path()).await.unwrap();
            assert_eq!(manager.status(), SealStatus::Unsealed);
            assert!(manager.is_dev_mode());
        }
    }

    #[tokio::test]
    async fn test_verify_root_token() {
        let (_tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 3,
            threshold: 2,
        };

        let init_result = manager.initialize(config).await.unwrap();

        assert!(manager
            .verify_root_token(&init_result.root_token)
            .await
            .unwrap());
        assert!(!manager.verify_root_token("wrong_token").await.unwrap());
    }

    #[tokio::test]
    async fn test_share_hex_roundtrip() {
        let share = Share {
            index: 1,
            data: vec![1, 2, 3, 4, 5],
        };

        let hex = share.to_hex();
        let decoded = Share::from_hex(&hex).unwrap();

        assert_eq!(share.data, decoded.data);
    }

    #[tokio::test]
    async fn test_invalid_config_threshold_zero() {
        let config = ShamirConfig {
            shares: 3,
            threshold: 0,
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_invalid_config_shares_less_than_threshold() {
        let config = ShamirConfig {
            shares: 2,
            threshold: 3,
        };
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_persistence_after_init() {
        let tmp = TempDir::new().unwrap();

        let root_token;
        let shares;

        // First instance - initialize
        {
            let mut manager = SealManager::new(tmp.path()).await.unwrap();
            let config = ShamirConfig {
                shares: 3,
                threshold: 2,
            };
            let result = manager.initialize(config).await.unwrap();
            root_token = result.root_token;
            shares = result.shares;
        }

        // Second instance - should be sealed
        {
            let mut manager = SealManager::new(tmp.path()).await.unwrap();
            assert_eq!(manager.status(), SealStatus::Sealed);

            // Should be able to unseal with same shares
            manager.unseal(&shares[0]).await.unwrap();
            manager.unseal(&shares[1]).await.unwrap();
            assert_eq!(manager.status(), SealStatus::Unsealed);

            // Root token should still work
            assert!(manager.verify_root_token(&root_token).await.unwrap());
        }
    }
}
