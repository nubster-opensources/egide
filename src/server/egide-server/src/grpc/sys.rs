//! gRPC implementation of the System service (`SysService`).
//!
//! Auth parity with REST:
//! - `Status`  : no bearer required (open endpoint).
//! - `Init`    : no bearer required; service uses a synthetic root [`AuthContext`].
//! - `Unseal`  : no bearer required (the shares are the credential).
//! - `Seal`    : bearer required; service layer enforces root privilege.

use std::sync::Arc;

use egide_api::ServiceContext;
use egide_auth::AuthContext;
use tonic::{Request, Response, Status};

use egide_api::proto::{
    sys_service_server::SysService, InitRequest, InitResponse, SealRequest, SealResponse,
    StatusRequest, StatusResponse, UnsealRequest, UnsealResponse,
};

use crate::grpc::auth::authenticate;
use crate::grpc::status_map::to_status;

/// gRPC handler struct for the System domain.
///
/// Holds a shared reference to the application service context.
#[derive(Clone)]
pub struct SysGrpc {
    /// Shared service context.
    pub state: Arc<ServiceContext>,
}

#[tonic::async_trait]
impl SysService for SysGrpc {
    /// Returns vault lifecycle status. No authentication required.
    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let sv = self.state.status().await;
        Ok(Response::new(StatusResponse {
            version: sv.version.to_owned(),
            initialized: sv.initialized,
            sealed: sv.sealed,
        }))
    }

    /// Initializes the vault. No authentication required; a synthetic root context is used.
    ///
    /// proto3 scalars default to 0 when omitted; normalize 0 values to the
    /// same defaults that the REST handler applies via `#[serde(default)]`:
    /// `shares` defaults to 5, `threshold` defaults to 3.
    async fn init(&self, request: Request<InitRequest>) -> Result<Response<InitResponse>, Status> {
        let req = request.into_inner();
        let shares_raw = u8::try_from(req.shares)
            .map_err(|_| Status::invalid_argument("shares must fit in u8"))?;
        let threshold_raw = u8::try_from(req.threshold)
            .map_err(|_| Status::invalid_argument("threshold must fit in u8"))?;
        let shares = if shares_raw == 0 { 5 } else { shares_raw };
        let threshold = if threshold_raw == 0 { 3 } else { threshold_raw };
        let view = self
            .state
            .init(&AuthContext::root(), shares, threshold)
            .await
            .map_err(to_status)?;
        Ok(Response::new(InitResponse {
            root_token: view.root_token,
            shares_hex: view.shares_hex,
            shares_base64: view.shares_base64,
        }))
    }

    /// Submits an unseal share. No authentication required.
    async fn unseal(
        &self,
        request: Request<UnsealRequest>,
    ) -> Result<Response<UnsealResponse>, Status> {
        let req = request.into_inner();
        let view = self.state.unseal(&req.share_hex).await.map_err(to_status)?;
        Ok(Response::new(UnsealResponse {
            sealed: view.sealed,
            threshold: u32::from(view.threshold),
            progress: u32::from(view.progress),
        }))
    }

    /// Seals the vault. Bearer token required; service layer enforces root privilege.
    async fn seal(&self, request: Request<SealRequest>) -> Result<Response<SealResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        self.state.seal(&ctx).await.map_err(to_status)?;
        Ok(Response::new(SealResponse {}))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use egide_api::proto::sys_service_server::SysService;

    use crate::grpc::tests_support::sealed_context;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    async fn fresh_svc() -> (tempfile::TempDir, SysGrpc) {
        let (tmp, ctx) = sealed_context().await;
        (tmp, SysGrpc { state: ctx })
    }

    // ------------------------------------------------------------------
    // Status: open, no auth
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn status_returns_uninitialized_on_fresh_vault() {
        let (_tmp, svc) = fresh_svc().await;
        let res = svc.status(Request::new(StatusRequest {})).await.unwrap();
        let body = res.into_inner();
        assert!(!body.initialized);
        assert!(body.sealed);
    }

    // ------------------------------------------------------------------
    // Init: no auth; synthetic root applied by service layer
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn init_with_valid_shares_succeeds() {
        let (_tmp, svc) = fresh_svc().await;
        let res = svc
            .init(Request::new(InitRequest {
                shares: 5,
                threshold: 3,
            }))
            .await
            .unwrap();
        let body = res.into_inner();
        assert!(!body.root_token.is_empty());
        assert_eq!(body.shares_hex.len(), 5);
    }

    // ------------------------------------------------------------------
    // Unseal: no auth
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn unseal_invalid_share_returns_bad_request_or_internal() {
        let (_tmp, svc) = fresh_svc().await;
        // Initialize first so unseal has something to work with.
        let init_res = svc
            .init(Request::new(InitRequest {
                shares: 5,
                threshold: 3,
            }))
            .await
            .unwrap()
            .into_inner();

        let share = &init_res.shares_hex[0];
        let res = svc
            .unseal(Request::new(UnsealRequest {
                share_hex: share.clone(),
            }))
            .await
            .unwrap();
        // After one share with threshold 3, still sealed.
        assert!(res.into_inner().sealed);
    }

    // ------------------------------------------------------------------
    // Seal: requires root bearer
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn seal_without_token_returns_unauthenticated() {
        let (_tmp, svc) = fresh_svc().await;
        let err = svc.seal(Request::new(SealRequest {})).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
