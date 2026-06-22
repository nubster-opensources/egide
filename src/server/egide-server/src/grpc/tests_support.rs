//! Shared test helpers for gRPC service unit tests.
//!
//! This module is compiled only in `#[cfg(test)]` contexts.

use std::sync::Arc;
use std::time::Instant;

use egide_auth::{
    AuthContext, AuthService, RootTokenBackend, ServiceTokenBackend, ServiceTokenStore,
};
use egide_seal::{SealManager, ShamirConfig};
use egide_storage::StorageBackend;
use tokio::sync::RwLock;

use egide_api::ServiceContext;

/// Builds an uninitialized, sealed [`ServiceContext`].
///
/// Useful for testing open endpoints (Status, Init, Unseal) that operate
/// before the vault is initialized.
pub(crate) async fn sealed_context() -> (tempfile::TempDir, Arc<ServiceContext>) {
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

/// Builds an initialized, fully unsealed [`ServiceContext`] and returns the root token.
///
/// Both secrets and transit engines are started. The root token can be used
/// directly as a bearer in gRPC request metadata.
pub(crate) async fn unsealed_context_with_token() -> (tempfile::TempDir, Arc<ServiceContext>, String)
{
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut seal_manager = SealManager::new(tmp.path()).await.expect("seal manager");
    let init = seal_manager
        .initialize(ShamirConfig {
            shares: 5,
            threshold: 3,
        })
        .await
        .expect("initialize");
    let root_token = init.root_token.clone();
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

    (tmp, ctx, root_token)
}

/// Builds a [`TransitGrpc`] with an unsealed context and a **service token** bearer.
///
/// Returns `(tempdir, TransitGrpc, service_token_string)` so tests can verify
/// that non-root callers are rejected from root-only RPCs.
pub(crate) async fn unsealed_context_with_service_token(
) -> (tempfile::TempDir, Arc<egide_api::ServiceContext>, String) {
    let (tmp, ctx, _root) = unsealed_context_with_token().await;
    let (_, svc_token) = ctx
        .create_service_token(&AuthContext::root(), "test-service")
        .await
        .expect("create service token");
    (tmp, ctx, svc_token)
}
