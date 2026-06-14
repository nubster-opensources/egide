//! gRPC bearer-token authentication helper.
//!
//! Extracts the `Authorization: Bearer <token>` header from gRPC request
//! metadata and validates it against the configured auth backends.

use std::sync::Arc;

use egide_api::ServiceContext;
use egide_auth::AuthContext;
use tonic::{Request, Status};

/// Resolves the bearer token from request metadata into an [`AuthContext`].
///
/// Returns `Status::unauthenticated` when the `authorization` metadata key is
/// absent, malformed, or carries an invalid token.
pub async fn authenticate<T>(
    req: &Request<T>,
    ctx: &Arc<ServiceContext>,
) -> Result<AuthContext, Status> {
    let token = req
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;
    ctx.auth
        .validate(token)
        .await
        .map_err(|_| Status::unauthenticated("invalid credentials"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Instant;

    use egide_auth::{AuthService, RootTokenBackend, ServiceTokenBackend, ServiceTokenStore};
    use egide_seal::{SealManager, ShamirConfig};
    use egide_storage::StorageBackend;
    use tokio::sync::RwLock;
    use tonic::Code;

    /// Builds a minimal `ServiceContext` with root-token + service-token auth.
    /// Secrets and transit engines are left as `None` — not needed for auth tests.
    async fn auth_context() -> (tempfile::TempDir, Arc<ServiceContext>, String) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let mut seal = SealManager::new(tmp.path()).await.expect("seal manager");
        let init = seal
            .initialize(ShamirConfig {
                shares: 5,
                threshold: 3,
            })
            .await
            .expect("initialize");
        let root_token = init.root_token.clone();
        for share in init.shares.iter().take(3) {
            seal.unseal(share).await.expect("unseal");
        }

        // `SealManager::storage()` returns a concrete `SqliteBackend`.
        // `RootTokenBackend` is generic over `S: StorageBackend`, so it takes the
        // concrete type directly. `ServiceTokenStore` requires `Arc<dyn StorageBackend>`,
        // so we coerce via an explicit type annotation.
        let dyn_storage: Arc<dyn StorageBackend> = Arc::new(seal.storage());
        let service_store = ServiceTokenStore::new(Arc::clone(&dyn_storage));
        let auth = AuthService::new(vec![
            Box::new(RootTokenBackend::new(Arc::new(seal.storage()))),
            Box::new(ServiceTokenBackend::new(service_store.clone())),
        ]);

        let ctx = Arc::new(ServiceContext {
            auth,
            seal: RwLock::new(seal),
            secrets: RwLock::new(None),
            transit: RwLock::new(None),
            data_dir: tmp.path().to_path_buf(),
            start_time: Instant::now(),
            version: "0.1.0-test",
            service_tokens: service_store,
        });

        (tmp, ctx, root_token)
    }

    #[tokio::test]
    async fn no_authorization_header_is_unauthenticated() {
        let (_tmp, ctx, _root) = auth_context().await;
        let req = Request::new(());
        let err = authenticate(&req, &ctx).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn valid_root_token_returns_root_context() {
        let (_tmp, ctx, root_token) = auth_context().await;
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            format!("Bearer {root_token}")
                .parse()
                .expect("valid header"),
        );
        let auth_ctx = authenticate(&req, &ctx).await.expect("should succeed");
        assert!(auth_ctx.is_root());
    }

    #[tokio::test]
    async fn invalid_token_is_unauthenticated() {
        let (_tmp, ctx, _root) = auth_context().await;
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            "Bearer wrongtoken".parse().expect("valid header"),
        );
        let err = authenticate(&req, &ctx).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn malformed_header_without_bearer_prefix_is_unauthenticated() {
        let (_tmp, ctx, root_token) = auth_context().await;
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            root_token.parse().expect("valid header value"),
        );
        let err = authenticate(&req, &ctx).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }
}
