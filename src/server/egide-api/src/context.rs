//! Transport-agnostic application context shared by REST and gRPC.

use std::path::PathBuf;
use std::time::Instant;

use tokio::sync::RwLock;

use egide_auth::{AuthService, ServiceTokenStore};
use egide_seal::{SealManager, SealStatus};
use egide_secrets::SecretsEngine;
use egide_transit::TransitEngine;

/// Shared application state, owned as `Arc<ServiceContext>` by every transport.
pub struct ServiceContext {
    /// Authentication service (composed backends).
    pub auth: AuthService,
    /// Seal manager (init/seal/unseal).
    pub seal: RwLock<SealManager>,
    /// Secrets engine (present only when unsealed).
    pub secrets: RwLock<Option<SecretsEngine>>,
    /// Transit engine (present only when unsealed).
    pub transit: RwLock<Option<TransitEngine>>,
    /// Data directory.
    pub data_dir: PathBuf,
    /// Server start time.
    pub start_time: Instant,
    /// Server version.
    pub version: &'static str,
    /// Native service token store (shared with the auth backend).
    pub service_tokens: ServiceTokenStore,
}

impl ServiceContext {
    /// Creates the secrets engine if unsealed.
    pub async fn ensure_secrets_engine(&self) -> Result<(), String> {
        let seal = self.seal.read().await;
        if seal.status() != SealStatus::Unsealed {
            return Err("Vault is sealed".into());
        }

        let master_key = seal
            .master_key()
            .ok_or_else(|| "Master key not available".to_string())?;

        let mut secrets = self.secrets.write().await;
        if secrets.is_none() {
            // Use "default" tenant for v0.1
            let engine = SecretsEngine::new(&self.data_dir, "default", master_key.clone())
                .await
                .map_err(|e| e.to_string())?;
            *secrets = Some(engine);
            tracing::info!("Secrets engine initialized");
        }
        Ok(())
    }

    /// Clears the secrets engine (called on seal).
    pub async fn clear_secrets_engine(&self) {
        let mut secrets = self.secrets.write().await;
        *secrets = None;
        tracing::info!("Secrets engine cleared");
    }

    /// Creates the transit engine if unsealed.
    pub async fn ensure_transit_engine(&self) -> Result<(), String> {
        let seal = self.seal.read().await;
        if seal.status() != SealStatus::Unsealed {
            return Err("Vault is sealed".into());
        }

        let master_key = seal
            .master_key()
            .ok_or_else(|| "Master key not available".to_string())?;

        let mut transit = self.transit.write().await;
        if transit.is_none() {
            let engine = TransitEngine::new(&self.data_dir, master_key.clone())
                .await
                .map_err(|e| e.to_string())?;
            *transit = Some(engine);
            tracing::info!("Transit engine initialized");
        }
        Ok(())
    }

    /// Clears the transit engine (called on seal).
    pub async fn clear_transit_engine(&self) {
        let mut transit = self.transit.write().await;
        *transit = None;
        tracing::info!("Transit engine cleared");
    }
}
