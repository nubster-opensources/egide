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

pub mod error;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use blahaj::{Share as SharkShare, Sharks};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag for master key verification.
const SEAL_VERIFY_TAG: &[u8] = b"egide-seal-verify-v1";

/// Environment variable that must be set to `"1"` to explicitly allow dev
/// mode. Dev mode stores the master key in cleartext, so activating it must
/// never be a default or accidental outcome.
const DEV_MODE_GUARD_ENV: &str = "EGIDE_UNSAFE_DEV_MODE";

/// Environment variable that, when set to `"production"` (case-insensitive),
/// forbids dev mode regardless of the explicit guard above.
const PRODUCTION_ENV_MARKER: &str = "EGIDE_ENV";

/// Value of [`PRODUCTION_ENV_MARKER`] that forbids dev mode.
const PRODUCTION_ENV_VALUE: &str = "production";

use egide_crypto::MasterKey;
use egide_storage::StorageBackend;
use egide_storage_sqlite::SqliteBackend;

pub use error::SealError;

/// Keys for system.db storage.
mod keys {
    pub(crate) const ROOT_TOKEN_HASH: &str = "root_token_hash";
    pub(crate) const SHAMIR_THRESHOLD: &str = "shamir_threshold";
    pub(crate) const SHAMIR_TOTAL: &str = "shamir_total";
    pub(crate) const INITIALIZED_AT: &str = "initialized_at";
    pub(crate) const DEV_MODE_KEY: &str = "dev_mode_master_key";
    pub(crate) const MASTER_KEY_HMAC: &str = "master_key_hmac";
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
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_encode(&self.data)
    }

    /// Decodes a share from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self, SealError> {
        let data = hex_decode(hex).map_err(|e| SealError::InvalidShare(e.clone()))?;
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
    pub(crate) storage: SqliteBackend,
    #[allow(dead_code)]
    data_path: PathBuf,
    status: SealStatus,
    master_key: Option<MasterKey>,
    pub(crate) pending_shares: Vec<SharkShare>,
    pub(crate) pending_indices: HashSet<u8>,
    threshold: u8,
    dev_mode: bool,
    /// Expected HMAC for master key verification (loaded at startup).
    expected_hmac: Option<Vec<u8>>,
}

impl SealManager {
    /// Creates a new `SealManager` with storage path.
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
            expected_hmac: None,
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

            // Load expected HMAC for master key verification
            self.expected_hmac = self.storage.get(keys::MASTER_KEY_HMAC).await?;

            // Check for dev mode
            if let Some(key_bytes) = self.storage.get(keys::DEV_MODE_KEY).await? {
                // The data directory was previously initialized in dev mode.
                // Auto-unsealing must be refused just like the initial
                // activation: a dev-mode data directory copied into a
                // production environment must not silently expose the
                // cleartext master key on restart.
                ensure_dev_mode_allowed(
                    explicit_dev_mode_guard_is_set(),
                    production_marker_is_present(),
                )?;

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
    #[must_use]
    pub fn status(&self) -> SealStatus {
        self.status
    }

    /// Returns true if running in dev mode.
    #[must_use]
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
        let master_key = MasterKey::generate().map_err(|e| SealError::Crypto(e.to_string()))?;

        // Compute HMAC for master key verification
        let master_key_hmac = compute_master_key_hmac(master_key.as_bytes())?;

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
        let root_token = generate_token(32)?;
        let root_token_hash = hash_token(&root_token)?;

        // Store configuration
        let now = current_unix_secs()?;

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
        self.storage
            .put(keys::MASTER_KEY_HMAC, &master_key_hmac)
            .await?;

        self.expected_hmac = Some(master_key_hmac);
        self.status = SealStatus::Sealed;
        self.threshold = config.threshold;

        info!("Vault initialized successfully");

        Ok(InitResult { root_token, shares })
    }

    /// Submits a share for unsealing.
    // Kept async to match the public API signature expected by callers; storage calls may be
    // added in a future version without a breaking change.
    #[allow(clippy::unused_async)]
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

        // pending_shares.len() is always bounded by self.threshold (a u8), so the cast is safe.
        #[allow(clippy::cast_possible_truncation)]
        let progress = self.pending_shares.len() as u8;
        Ok(UnsealProgress {
            sealed: self.status == SealStatus::Sealed,
            threshold: self.threshold,
            progress,
        })
    }

    /// Reconstructs the master key from pending shares.
    fn reconstruct_master_key(&mut self) -> Result<(), SealError> {
        let sharks = Sharks(self.threshold);

        let secret = sharks
            .recover(&self.pending_shares)
            .map_err(|_| SealError::ReconstructionFailed)?;

        // Verify the reconstructed key matches expected HMAC
        let expected_hmac = self.expected_hmac.as_ref().ok_or_else(|| {
            warn!("Master key reconstruction failed - missing expected HMAC (data corruption?)");
            self.pending_shares.clear();
            self.pending_indices.clear();
            SealError::ReconstructionFailed
        })?;

        let computed_hmac = compute_master_key_hmac(&secret)?;
        if !hmac_tags_match(&computed_hmac, expected_hmac) {
            warn!("Master key reconstruction failed - HMAC mismatch (invalid shares?)");
            // Clear pending shares before returning error
            self.pending_shares.clear();
            self.pending_indices.clear();
            return Err(SealError::ReconstructionFailed);
        }

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
    #[must_use]
    pub fn master_key(&self) -> Option<&MasterKey> {
        self.master_key.as_ref()
    }

    /// Enables dev mode (auto-unseal).
    ///
    /// WARNING: Never use in production! Dev mode stores the master key in
    /// cleartext. Activation is refused unless the `EGIDE_UNSAFE_DEV_MODE`
    /// environment variable is set to `"1"` and no release/production
    /// marker is present. Dev mode is refused by default.
    pub async fn enable_dev_mode(&mut self) -> Result<(), SealError> {
        ensure_dev_mode_allowed(
            explicit_dev_mode_guard_is_set(),
            production_marker_is_present(),
        )?;

        self.enable_dev_mode_unchecked().await
    }

    /// Enables dev mode without checking the environment guard.
    ///
    /// Only reachable after [`SealManager::enable_dev_mode`] already
    /// checked the guard, or from tests that need dev mode as a fixture
    /// without depending on process environment state.
    async fn enable_dev_mode_unchecked(&mut self) -> Result<(), SealError> {
        if self.status != SealStatus::Uninitialized {
            return Err(SealError::AlreadyInitialized);
        }

        warn!("⚠️  ENABLING DEV MODE - NOT FOR PRODUCTION ⚠️");

        // Generate and store master key in plaintext
        let master_key = MasterKey::generate().map_err(|e| SealError::Crypto(e.to_string()))?;

        // Compute HMAC for master key verification (consistency with initialize)
        let master_key_hmac = compute_master_key_hmac(master_key.as_bytes())?;

        // Generate root token
        let root_token = generate_token(32)?;
        let root_token_hash = hash_token(&root_token)?;

        let now = current_unix_secs()?;

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
        self.storage
            .put(keys::MASTER_KEY_HMAC, &master_key_hmac)
            .await?;

        self.expected_hmac = Some(master_key_hmac);
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

    /// Returns a clone of the storage backend.
    ///
    /// This is useful for external components that need to read system data.
    #[must_use]
    pub fn storage(&self) -> SqliteBackend {
        self.storage.clone()
    }
}

/// Returns the current time as seconds since the UNIX epoch.
///
/// Returns a [`SealError::Crypto`] if the system clock is set before the UNIX epoch.
fn current_unix_secs() -> Result<u64, SealError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| SealError::Crypto(format!("system clock error: {e}")))
}

/// Computes HMAC-SHA256 of the master key for verification.
///
/// Returns a [`SealError::Crypto`] if the underlying MAC construction fails,
/// which cannot occur in practice for HMAC-SHA256 with any key length.
fn compute_master_key_hmac(master_key: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut mac = HmacSha256::new_from_slice(master_key)
        .map_err(|e| SealError::Crypto(format!("HMAC construction failed: {e}")))?;
    mac.update(SEAL_VERIFY_TAG);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Compares two HMAC tags in constant time.
///
/// A plain `!=` on byte slices short-circuits at the first differing byte,
/// which leaks the length of the matching prefix through timing. This uses
/// [`subtle::ConstantTimeEq`] so the comparison time does not depend on the
/// tag contents. Tag lengths are not secret (SHA-256 tags are always 32
/// bytes), so a length mismatch may return early.
fn hmac_tags_match(computed: &[u8], expected: &[u8]) -> bool {
    computed.ct_eq(expected).into()
}

/// Generates a random token as hex string.
///
/// Returns a [`SealError::Crypto`] if the operating system's CSPRNG fails
/// to produce output.
fn generate_token(bytes: usize) -> Result<String, SealError> {
    use rand::TryRng;
    let mut buf = Zeroizing::new(vec![0u8; bytes]);
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| SealError::Crypto(e.to_string()))?;
    Ok(hex_encode(&buf))
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
///
/// Operates on bytes rather than string slice ranges, so a non-ASCII input
/// (which may contain multi-byte UTF-8 characters) is rejected with an error
/// instead of panicking on a misaligned char boundary.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.is_ascii() {
        return Err("hex string must contain only ASCII characters".into());
    }
    if !hex.len().is_multiple_of(2) {
        return Err("odd length hex string".into());
    }

    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = hex_digit_value(pair[0])?;
            let low = hex_digit_value(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

/// Converts a single ASCII byte into its hex digit value.
fn hex_digit_value(byte: u8) -> Result<u8, String> {
    // `to_digit(16)` only ever returns values in 0..16, so the truncating
    // cast to u8 is always exact.
    #[allow(clippy::cast_possible_truncation)]
    let value = (byte as char)
        .to_digit(16)
        .map(|digit| digit as u8)
        .ok_or_else(|| format!("invalid hex digit: {}", byte as char))?;
    Ok(value)
}

/// Returns true when the operator explicitly opted into dev mode for this
/// process via [`DEV_MODE_GUARD_ENV`].
fn explicit_dev_mode_guard_is_set() -> bool {
    std::env::var(DEV_MODE_GUARD_ENV).is_ok_and(|value| value == "1")
}

/// Returns true when dev mode must be refused because the process runs in
/// a production configuration.
///
/// Release builds categorically refuse dev mode: `cfg!(not(debug_assertions))`
/// makes the marker unconditionally present in any optimized build, and no
/// environment variable can override it. Debug builds additionally treat an
/// explicit `EGIDE_ENV=production` marker as production.
fn production_marker_is_present() -> bool {
    cfg!(not(debug_assertions))
        || std::env::var(PRODUCTION_ENV_MARKER)
            .is_ok_and(|value| value.eq_ignore_ascii_case(PRODUCTION_ENV_VALUE))
}

/// Decides whether dev mode may be activated, given the resolved guard
/// state.
///
/// Kept separate from environment access so the decision logic can be
/// exercised directly in tests without mutating process environment
/// variables, which requires `unsafe` code since Rust 1.82 and this crate
/// forbids unsafe code entirely.
fn ensure_dev_mode_allowed(
    explicit_guard_present: bool,
    production_marker_present: bool,
) -> Result<(), SealError> {
    if production_marker_present {
        return Err(SealError::DevModeForbidden(
            "a release or production build marker is present".into(),
        ));
    }
    if !explicit_guard_present {
        return Err(SealError::DevModeForbidden(format!(
            "set {DEV_MODE_GUARD_ENV}=1 to explicitly opt into dev mode"
        )));
    }
    Ok(())
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
                // i iterates 0..3, so i+1 is always in [1,3]; cast is safe in this test.
                #[allow(clippy::cast_possible_truncation)]
                let expected_progress = (i + 1) as u8;
                assert_eq!(progress.progress, expected_progress);
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
    async fn test_enable_dev_mode_refuses_without_explicit_guard_by_default() {
        let (_tmp, mut manager) = setup().await;

        let result = manager.enable_dev_mode().await;

        assert!(
            result.is_err(),
            "dev mode must not activate without an explicit environment guard"
        );
    }

    #[tokio::test]
    async fn test_dev_mode() {
        let (_tmp, mut manager) = setup().await;

        // Bypasses the environment guard: this test covers dev mode's
        // effects (status, master key), not the guard itself, which has
        // its own dedicated tests below.
        manager.enable_dev_mode_unchecked().await.unwrap();

        assert_eq!(manager.status(), SealStatus::Unsealed);
        assert!(manager.is_dev_mode());
        assert!(manager.master_key().is_some());
    }

    #[tokio::test]
    async fn test_dev_mode_auto_unseal_on_restart_requires_guard() {
        let tmp = TempDir::new().unwrap();

        // First instance - enable dev mode via the test-only bypass.
        {
            let mut manager = SealManager::new(tmp.path()).await.unwrap();
            manager.enable_dev_mode_unchecked().await.unwrap();
        }

        // Second instance - restart must refuse to auto-unseal without the
        // explicit environment guard, even though the data directory was
        // previously initialized in dev mode.
        {
            let result = SealManager::new(tmp.path()).await;
            assert!(matches!(result, Err(SealError::DevModeForbidden(_))));
        }
    }

    #[test]
    fn test_dev_mode_guard_requires_explicit_marker() {
        let result = ensure_dev_mode_allowed(false, false);
        assert!(matches!(result, Err(SealError::DevModeForbidden(_))));
    }

    #[test]
    fn test_dev_mode_guard_refuses_in_production_configuration() {
        let result = ensure_dev_mode_allowed(true, true);
        assert!(
            matches!(result, Err(SealError::DevModeForbidden(_))),
            "the production marker must forbid dev mode even with the explicit guard set"
        );
    }

    #[test]
    fn test_dev_mode_guard_refuses_production_without_explicit_marker() {
        let result = ensure_dev_mode_allowed(false, true);
        assert!(matches!(result, Err(SealError::DevModeForbidden(_))));
    }

    #[test]
    fn test_dev_mode_guard_allows_explicit_marker_outside_production() {
        let result = ensure_dev_mode_allowed(true, false);
        assert!(result.is_ok());
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

    #[test]
    fn from_hex_rejects_non_ascii_input_without_panicking() {
        // "0e0" with the middle byte replaced by a two-byte UTF-8 character.
        // The total byte length is even, but slicing by fixed byte offsets
        // lands mid-character, which must be rejected rather than panic.
        let result = Share::from_hex("0\u{e9}0");
        assert!(matches!(result, Err(SealError::InvalidShare(_))));
    }

    #[test]
    fn hex_decode_rejects_non_ascii_input_without_panicking() {
        let result = hex_decode("0\u{e9}0");
        assert!(result.is_err());
    }

    #[test]
    fn from_hex_rejects_odd_length_input() {
        let result = Share::from_hex("abc");
        assert!(matches!(result, Err(SealError::InvalidShare(_))));
    }

    #[test]
    fn from_hex_rejects_non_hex_ascii_digits() {
        let result = Share::from_hex("zz");
        assert!(matches!(result, Err(SealError::InvalidShare(_))));
    }

    #[test]
    fn from_hex_rejects_empty_input() {
        let result = Share::from_hex("");
        assert!(matches!(result, Err(SealError::InvalidShare(_))));
    }

    #[test]
    fn hmac_tags_match_accepts_equal_tags() {
        let tag = [0x42u8; 32];
        assert!(hmac_tags_match(&tag, &tag));
    }

    #[test]
    fn hmac_tags_match_rejects_difference_in_first_byte() {
        let expected = [0x42u8; 32];
        let mut computed = expected;
        computed[0] ^= 0x01;
        assert!(!hmac_tags_match(&computed, &expected));
    }

    #[test]
    fn hmac_tags_match_rejects_difference_in_last_byte() {
        let expected = [0x42u8; 32];
        let mut computed = expected;
        computed[31] ^= 0x01;
        assert!(!hmac_tags_match(&computed, &expected));
    }

    #[test]
    fn hmac_tags_match_rejects_length_mismatch() {
        let expected = [0x42u8; 32];
        let computed = [0x42u8; 16];
        assert!(!hmac_tags_match(&computed, &expected));
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

    #[tokio::test]
    async fn test_unseal_with_invalid_shares_fails() {
        let tmp_a = TempDir::new().unwrap();
        let tmp_b = TempDir::new().unwrap();

        let config = ShamirConfig {
            shares: 3,
            threshold: 2,
        };

        // Initialize vault A
        let mut manager_a = SealManager::new(tmp_a.path()).await.unwrap();
        manager_a.initialize(config.clone()).await.unwrap();

        // Initialize vault B (different master key)
        let mut manager_b = SealManager::new(tmp_b.path()).await.unwrap();
        let result_b = manager_b.initialize(config).await.unwrap();

        // Try to unseal vault A with shares from vault B
        // This should fail because the reconstructed key won't match the expected HMAC
        manager_a.unseal(&result_b.shares[0]).await.unwrap();
        let result = manager_a.unseal(&result_b.shares[1]).await;

        assert!(matches!(result, Err(SealError::ReconstructionFailed)));
        assert_eq!(manager_a.status(), SealStatus::Sealed);
    }

    #[tokio::test]
    async fn test_unseal_missing_hmac_fails() {
        let (tmp, mut manager) = setup().await;

        let config = ShamirConfig {
            shares: 3,
            threshold: 2,
        };

        let init_result = manager.initialize(config).await.unwrap();

        // Simulate corrupted storage missing the expected HMAC
        manager.storage.delete(keys::MASTER_KEY_HMAC).await.unwrap();

        // Simulate restart where verification material is missing
        drop(manager);
        let mut manager = SealManager::new(tmp.path()).await.unwrap();

        // Even with enough shares, reconstruction should be rejected
        manager.unseal(&init_result.shares[0]).await.unwrap();
        let result = manager.unseal(&init_result.shares[1]).await;

        assert!(matches!(result, Err(SealError::ReconstructionFailed)));
        assert_eq!(manager.status(), SealStatus::Sealed);
        assert!(manager.pending_shares.is_empty());
        assert!(manager.pending_indices.is_empty());
    }
}
