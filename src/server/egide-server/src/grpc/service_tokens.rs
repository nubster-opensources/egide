//! gRPC implementation of the `ServiceToken` service (`ServiceTokenService`).
//!
//! Auth parity with REST handlers in `lib.rs`:
//! All three operations require a bearer token; the service layer enforces
//! root privilege (returns `Forbidden` for non-root callers).

use std::sync::Arc;

use egide_api::ServiceContext;
use tonic::{Request, Response, Status};

use egide_api::proto::{
    service_token_service_server::ServiceTokenService, CreateServiceTokenRequest,
    CreateServiceTokenResponse, ListServiceTokensRequest, ListServiceTokensResponse,
    RevokeServiceTokenRequest, RevokeServiceTokenResponse,
    ServiceTokenRecord as ProtoServiceTokenRecord,
};

use crate::grpc::auth::authenticate;
use crate::grpc::status_map::to_status;

/// gRPC handler struct for the `ServiceToken` domain.
///
/// Holds a shared reference to the application service context.
#[derive(Clone)]
pub struct ServiceTokenGrpc {
    /// Shared service context.
    pub state: Arc<ServiceContext>,
}

#[tonic::async_trait]
impl ServiceTokenService for ServiceTokenGrpc {
    /// Creates a new service token. Bearer + root required.
    async fn create(
        &self,
        request: Request<CreateServiceTokenRequest>,
    ) -> Result<Response<CreateServiceTokenResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let (token_id, raw_token) = self
            .state
            .create_service_token(&ctx, &req.service_name)
            .await
            .map_err(to_status)?;
        Ok(Response::new(CreateServiceTokenResponse {
            token_id,
            raw_token,
        }))
    }

    /// Lists all service token records. Bearer + root required.
    async fn list(
        &self,
        request: Request<ListServiceTokensRequest>,
    ) -> Result<Response<ListServiceTokensResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        let records = self
            .state
            .list_service_tokens(&ctx)
            .await
            .map_err(to_status)?;
        let proto_records = records
            .into_iter()
            .map(|r| ProtoServiceTokenRecord {
                token_id: r.token_id,
                service_name: r.service_name,
                // The auth layer stores an optional revocation timestamp;
                // the proto exposes a boolean flag.
                revoked: r.revoked_at.is_some(),
                created_at: r.created_at,
            })
            .collect();
        Ok(Response::new(ListServiceTokensResponse {
            records: proto_records,
        }))
    }

    /// Revokes a service token by identifier. Bearer + root required.
    async fn revoke(
        &self,
        request: Request<RevokeServiceTokenRequest>,
    ) -> Result<Response<RevokeServiceTokenResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        self.state
            .revoke_service_token(&ctx, &req.token_id)
            .await
            .map_err(to_status)?;
        Ok(Response::new(RevokeServiceTokenResponse {}))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use egide_api::proto::service_token_service_server::ServiceTokenService;
    use tonic::Code;

    use crate::grpc::tests_support::unsealed_context_with_token;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    async fn fresh_svc_root() -> (tempfile::TempDir, ServiceTokenGrpc, String) {
        let (tmp, ctx, root) = unsealed_context_with_token().await;
        let svc = ServiceTokenGrpc { state: ctx };
        (tmp, svc, root)
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
    async fn create_without_token_returns_unauthenticated() {
        let (_tmp, svc, _tok) = fresh_svc_root().await;
        let err = svc
            .create(Request::new(CreateServiceTokenRequest {
                service_name: "svc".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    // ------------------------------------------------------------------
    // Non-root -> PermissionDenied
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn create_with_service_token_returns_permission_denied() {
        let (tmp, ctx, _root_token) = unsealed_context_with_token().await;
        // Create a service token to use as a non-root bearer.
        let (_, svc_token) = ctx
            .create_service_token(&egide_auth::AuthContext::root(), "identity")
            .await
            .unwrap();
        let svc = ServiceTokenGrpc { state: ctx };
        let err = svc
            .create(authed(
                CreateServiceTokenRequest {
                    service_name: "platform".into(),
                },
                &svc_token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        drop(tmp);
    }

    // ------------------------------------------------------------------
    // Happy path: create + list + revoke
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn create_list_revoke_round_trip() {
        let (_tmp, svc, root) = fresh_svc_root().await;

        // Create.
        let create_res = svc
            .create(authed(
                CreateServiceTokenRequest {
                    service_name: "identity".into(),
                },
                &root,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!create_res.token_id.is_empty());
        assert!(!create_res.raw_token.is_empty());
        let token_id = create_res.token_id;

        // List.
        let list_res = svc
            .list(authed(ListServiceTokensRequest {}, &root))
            .await
            .unwrap()
            .into_inner();
        assert!(list_res
            .records
            .iter()
            .any(|r| r.token_id == token_id && !r.revoked));

        // Revoke.
        svc.revoke(authed(
            RevokeServiceTokenRequest {
                token_id: token_id.clone(),
            },
            &root,
        ))
        .await
        .unwrap();

        // List again - entry should now be revoked.
        let list_after = svc
            .list(authed(ListServiceTokensRequest {}, &root))
            .await
            .unwrap()
            .into_inner();
        let record = list_after
            .records
            .iter()
            .find(|r| r.token_id == token_id)
            .unwrap();
        assert!(record.revoked);
    }
}
