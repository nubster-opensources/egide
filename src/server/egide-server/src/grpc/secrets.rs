//! gRPC implementation of the Secrets service (`SecretsService`).
//!
//! Auth parity with REST: all four operations require a bearer token.
//! No root privilege is checked; the service layer is open to any
//! authenticated caller.

use std::sync::Arc;

use egide_api::ServiceContext;
use tonic::{Request, Response, Status};

use egide_api::proto::{
    secrets_service_server::SecretsService, DeleteSecretRequest, DeleteSecretResponse,
    GetSecretRequest, GetSecretResponse, ListSecretsRequest, ListSecretsResponse, PutSecretRequest,
    PutSecretResponse, SecretMeta,
};

use crate::grpc::auth::authenticate;
use crate::grpc::status_map::to_status;

/// gRPC handler struct for the Secrets domain.
///
/// Holds a shared reference to the application service context.
#[derive(Clone)]
pub struct SecretsGrpc {
    /// Shared service context.
    pub state: Arc<ServiceContext>,
}

#[tonic::async_trait]
impl SecretsService for SecretsGrpc {
    /// Retrieves the current version of a secret. Bearer token required.
    async fn get(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<GetSecretResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let view = self.state.secret_get(&req.path).await.map_err(to_status)?;
        Ok(Response::new(GetSecretResponse {
            data: view.data,
            version: view.version,
            created_at: view.created_at,
        }))
    }

    /// Stores or updates a secret. Bearer token required.
    ///
    /// The proto encodes the optional CAS field via `has_cas: bool` + `cas: u32`.
    async fn put(
        &self,
        request: Request<PutSecretRequest>,
    ) -> Result<Response<PutSecretResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let cas = if req.has_cas { Some(req.cas) } else { None };
        let version = self
            .state
            .secret_put(&req.path, req.data, cas)
            .await
            .map_err(to_status)?;
        Ok(Response::new(PutSecretResponse { version }))
    }

    /// Soft-deletes a secret. Bearer token required.
    async fn delete(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<DeleteSecretResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        self.state
            .secret_delete(&req.path)
            .await
            .map_err(to_status)?;
        Ok(Response::new(DeleteSecretResponse {}))
    }

    /// Lists secrets whose path starts with the given prefix. Bearer token required.
    async fn list(
        &self,
        request: Request<ListSecretsRequest>,
    ) -> Result<Response<ListSecretsResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let metas = self
            .state
            .secret_list(&req.prefix)
            .await
            .map_err(to_status)?;
        let entries = metas
            .into_iter()
            .map(|m| SecretMeta {
                path: m.path,
                version: m.version,
                created_at: m.created_at,
            })
            .collect();
        Ok(Response::new(ListSecretsResponse { entries }))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use egide_api::proto::secrets_service_server::SecretsService;

    use crate::grpc::tests_support::unsealed_context_with_token;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    async fn fresh_svc() -> (tempfile::TempDir, SecretsGrpc, String) {
        let (tmp, ctx, token) = unsealed_context_with_token().await;
        let svc = SecretsGrpc { state: ctx };
        (tmp, svc, token)
    }

    fn authed<T>(inner: T, token: &str) -> Request<T> {
        let mut req = Request::new(inner);
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    // ------------------------------------------------------------------
    // No auth -> Unauthenticated
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn get_without_token_returns_unauthenticated() {
        let (_tmp, svc, _tok) = fresh_svc().await;
        let err = svc
            .get(Request::new(GetSecretRequest { path: "x/y".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // ------------------------------------------------------------------
    // Sealed -> Unavailable
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn get_while_sealed_returns_unavailable() {
        use crate::grpc::tests_support::unsealed_context_with_token;
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        // Seal the vault.
        let auth_ctx = egide_auth::AuthContext::root();
        ctx.seal(&auth_ctx).await.unwrap();

        let svc = SecretsGrpc { state: ctx };
        let err = svc
            .get(authed(GetSecretRequest { path: "x".into() }, &root_token))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    // ------------------------------------------------------------------
    // Happy path: put then get round-trip
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let (_tmp, svc, token) = fresh_svc().await;
        let data: std::collections::HashMap<String, String> =
            [("key".to_string(), "value".to_string())].into();

        let put_res = svc
            .put(authed(
                PutSecretRequest {
                    path: "app/config".into(),
                    data: data.clone(),
                    has_cas: false,
                    cas: 0,
                },
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(put_res.into_inner().version, 1);

        let get_res = svc
            .get(authed(
                GetSecretRequest {
                    path: "app/config".into(),
                },
                &token,
            ))
            .await
            .unwrap();
        let body = get_res.into_inner();
        assert_eq!(body.version, 1);
        assert_eq!(body.data.get("key").map(String::as_str), Some("value"));
    }
}
