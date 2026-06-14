//! Test helpers shared across all service-layer test modules.
//!
//! This module is only compiled in `#[cfg(test)]` contexts.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use egide_auth::{AuthService, RootTokenBackend, ServiceTokenBackend, ServiceTokenStore};
use egide_seal::{SealManager, ShamirConfig};
use egide_storage::StorageBackend;

use crate::ServiceContext;

/// Builds an initialized, fully unsealed [`ServiceContext`] backed by a temporary directory.
///
/// The seal manager is initialized with 5 shares / threshold 3 and unsealed with 3 shares.
/// Both secrets and transit engines are started.
///
/// Returns the [`tempfile::TempDir`] (must be held alive for the duration of the test)
/// and an `Arc<ServiceContext>` ready to use.
pub(crate) async fn unsealed_context() -> (tempfile::TempDir, Arc<ServiceContext>) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut seal_manager = SealManager::new(tmp.path()).await.expect("seal manager");
    let init = seal_manager
        .initialize(ShamirConfig {
            shares: 5,
            threshold: 3,
        })
        .await
        .expect("initialize");

    for share in init.shares.iter().take(3) {
        seal_manager.unseal(share).await.expect("unseal share");
    }

    let storage: Arc<dyn StorageBackend> = Arc::new(seal_manager.storage());
    let service_store = ServiceTokenStore::new(storage);
    let auth = AuthService::new(vec![
        Box::new(RootTokenBackend::new(Arc::new(seal_manager.storage()))),
        Box::new(ServiceTokenBackend::new(service_store.clone())),
    ]);

    let ctx = Arc::new(ServiceContext {
        auth,
        seal: RwLock::new(seal_manager),
        secrets: RwLock::new(None),
        transit: RwLock::new(None),
        data_dir: tmp.path().to_path_buf(),
        start_time: Instant::now(),
        version: "0.1.0-test",
        service_tokens: service_store,
    });

    ctx.ensure_secrets_engine()
        .await
        .expect("secrets engine init");
    ctx.ensure_transit_engine()
        .await
        .expect("transit engine init");

    (tmp, ctx)
}

/// Builds a completely uninitialized [`ServiceContext`] backed by a temporary directory.
///
/// The seal manager has never been initialized: no Shamir shares, no root token.
/// Use this when testing behavior that requires the vault to be in the
/// `Uninitialized` state, such as verifying that `init` rejects an invalid
/// Shamir configuration.
///
/// Returns the [`tempfile::TempDir`] (must be held alive for the duration of the test)
/// and an `Arc<ServiceContext>`.
pub(crate) async fn uninitialized_context() -> (tempfile::TempDir, Arc<ServiceContext>) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let seal_manager = SealManager::new(tmp.path()).await.expect("seal manager");

    let storage: Arc<dyn StorageBackend> = Arc::new(seal_manager.storage());
    let service_store = ServiceTokenStore::new(storage);
    let auth = AuthService::new(vec![
        Box::new(RootTokenBackend::new(Arc::new(seal_manager.storage()))),
        Box::new(ServiceTokenBackend::new(service_store.clone())),
    ]);

    let ctx = Arc::new(ServiceContext {
        auth,
        seal: RwLock::new(seal_manager),
        secrets: RwLock::new(None),
        transit: RwLock::new(None),
        data_dir: tmp.path().to_path_buf(),
        start_time: Instant::now(),
        version: "0.1.0-test",
        service_tokens: service_store,
    });

    (tmp, ctx)
}
