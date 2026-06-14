//! System domain service methods: status, init, unseal, seal.

use egide_auth::AuthContext;
use egide_seal::{SealError, SealStatus, ShamirConfig, Share};

use crate::{ServiceContext, ServiceError};

/// Snapshot of the vault system status.
#[derive(Debug)]
pub struct StatusView {
    /// Server version string.
    pub version: &'static str,
    /// Whether the vault has been initialized (Shamir shares distributed).
    pub initialized: bool,
    /// Whether the vault is currently sealed (master key not in memory).
    pub sealed: bool,
}

/// Result of a successful vault initialization.
#[derive(Debug)]
pub struct InitView {
    /// Root token shown exactly once; store it securely.
    pub root_token: String,
    /// Shamir key shares in hex encoding, one per holder.
    pub shares_hex: Vec<String>,
    /// Shamir key shares in standard base64 encoding (raw share bytes).
    ///
    /// Computed from the same source as `shares_hex`: the raw `Share::data` bytes.
    /// Provided so REST adapters can reproduce the `keys_base64` field without
    /// re-decoding hex, preserving byte-identical responses.
    pub shares_base64: Vec<String>,
}

/// Progress snapshot returned after each unseal share submission.
#[derive(Debug)]
pub struct UnsealView {
    /// Whether the vault is still sealed.
    pub sealed: bool,
    /// Threshold required to unseal.
    pub threshold: u8,
    /// Number of valid shares submitted so far.
    pub progress: u8,
}

impl ServiceContext {
    /// Returns a system status snapshot.
    ///
    /// Open to any caller; the transport layer may apply additional gating.
    pub async fn status(&self) -> StatusView {
        let seal = self.seal.read().await;
        let st = seal.status();
        StatusView {
            version: self.version,
            initialized: st != SealStatus::Uninitialized,
            sealed: st != SealStatus::Unsealed,
        }
    }

    /// Initializes the vault by generating Shamir shares and a root token.
    ///
    /// Requires a root [`AuthContext`]; returns [`ServiceError::Forbidden`] otherwise.
    /// Returns [`ServiceError::BadRequest`] if the vault is already initialized or if
    /// the Shamir configuration is invalid (e.g. threshold is 0, or shares < threshold).
    pub async fn init(
        &self,
        ctx: &AuthContext,
        shares: u8,
        threshold: u8,
    ) -> Result<InitView, ServiceError> {
        if !ctx.is_root() {
            return Err(ServiceError::Forbidden("init requires root".into()));
        }
        let config = ShamirConfig { shares, threshold };
        let mut seal = self.seal.write().await;
        if seal.status() != SealStatus::Uninitialized {
            return Err(ServiceError::BadRequest("already initialized".into()));
        }
        let res = seal.initialize(config).await.map_err(|e| match e {
            SealError::InvalidConfig(msg) => ServiceError::BadRequest(msg),
            other => ServiceError::Internal(other.to_string()),
        })?;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        Ok(InitView {
            root_token: res.root_token,
            shares_hex: res.shares.iter().map(|s| s.to_hex()).collect(),
            shares_base64: res.shares.iter().map(|s| BASE64.encode(&s.data)).collect(),
        })
    }

    /// Submits one unseal share.
    ///
    /// Open to any caller (the share itself is the credential).
    /// Returns [`ServiceError::BadRequest`] if the vault is not initialized or the share is invalid.
    pub async fn unseal(&self, share_hex: &str) -> Result<UnsealView, ServiceError> {
        let share = Share::from_hex(share_hex)
            .map_err(|e| ServiceError::BadRequest(format!("invalid key: {e}")))?;
        let progress = {
            let mut seal = self.seal.write().await;
            match seal.status() {
                SealStatus::Uninitialized => {
                    return Err(ServiceError::BadRequest("not initialized".into()))
                },
                SealStatus::Unsealed => {
                    return Ok(UnsealView {
                        sealed: false,
                        threshold: 0,
                        progress: 0,
                    })
                },
                SealStatus::Sealed => seal
                    .unseal(&share)
                    .await
                    .map_err(|e| ServiceError::BadRequest(e.to_string()))?,
            }
        };
        if !progress.sealed {
            self.ensure_secrets_engine()
                .await
                .map_err(ServiceError::Internal)?;
            self.ensure_transit_engine()
                .await
                .map_err(ServiceError::Internal)?;
        }
        Ok(UnsealView {
            sealed: progress.sealed,
            threshold: progress.threshold,
            progress: progress.progress,
        })
    }

    /// Seals the vault, wiping the master key from memory.
    ///
    /// Requires a root [`AuthContext`]; returns [`ServiceError::Forbidden`] otherwise.
    /// Returns [`ServiceError::BadRequest`] if the vault is not currently unsealed.
    pub async fn seal(&self, ctx: &AuthContext) -> Result<(), ServiceError> {
        if !ctx.is_root() {
            return Err(ServiceError::Forbidden("seal requires root".into()));
        }
        {
            let mut seal = self.seal.write().await;
            if seal.status() != SealStatus::Unsealed {
                return Err(ServiceError::BadRequest("not unsealed".into()));
            }
            seal.seal();
        }
        self.clear_secrets_engine().await;
        self.clear_transit_engine().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egide_auth::{AuthContext, AuthMethod};

    use crate::test_support::{uninitialized_context, unsealed_context};

    #[tokio::test]
    async fn status_reports_unsealed() {
        let (_t, c) = unsealed_context().await;
        let s = c.status().await;
        assert!(!s.sealed, "vault should be unsealed");
        assert!(s.initialized, "vault should be initialized");
    }

    #[tokio::test]
    async fn seal_requires_root() {
        let (_t, c) = unsealed_context().await;
        let non_root = AuthContext {
            account_id: "svc".into(),
            email: None,
            display_name: None,
            auth_method: AuthMethod::ServiceToken,
            expires_at: None,
        };
        let err = c.seal(&non_root).await.unwrap_err();
        assert!(
            matches!(err, ServiceError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
    }

    #[tokio::test]
    async fn seal_root_succeeds_and_reports_sealed() {
        let (_t, c) = unsealed_context().await;
        c.seal(&AuthContext::root()).await.expect("seal");
        let s = c.status().await;
        assert!(s.sealed, "vault should be sealed after seal()");
    }

    #[tokio::test]
    async fn init_requires_root() {
        let (_t, c) = unsealed_context().await;
        let non_root = AuthContext {
            account_id: "x".into(),
            email: None,
            display_name: None,
            auth_method: AuthMethod::ServiceToken,
            expires_at: None,
        };
        let err = c.init(&non_root, 5, 3).await.unwrap_err();
        assert!(
            matches!(err, ServiceError::Forbidden(_)),
            "expected Forbidden, got {err:?}"
        );
    }

    #[tokio::test]
    async fn init_already_initialized_returns_bad_request() {
        let (_t, c) = unsealed_context().await;
        let err = c.init(&AuthContext::root(), 5, 3).await.unwrap_err();
        assert!(
            matches!(err, ServiceError::BadRequest(_)),
            "expected BadRequest, got {err:?}"
        );
    }

    #[tokio::test]
    async fn init_with_invalid_config_is_bad_request() {
        // threshold=0 is rejected by ShamirConfig::validate() as InvalidConfig.
        // Must return BadRequest (400), not Internal (500), on both transports.
        let (_t, c) = uninitialized_context().await;
        let err = c.init(&AuthContext::root(), 0, 0).await.unwrap_err();
        assert!(
            matches!(err, ServiceError::BadRequest(_)),
            "expected BadRequest for invalid Shamir config, got {err:?}"
        );
    }
}
