//! gRPC transport layer for Egide server.

pub mod auth;
pub mod secrets;
pub mod service_tokens;
pub mod status_map;
pub mod sys;
pub mod transit;

#[cfg(test)]
pub(crate) mod tests_support;

pub use secrets::SecretsGrpc;
pub use service_tokens::ServiceTokenGrpc;
pub use sys::SysGrpc;
pub use transit::TransitGrpc;

use std::net::SocketAddr;
use std::sync::Arc;

use egide_api::proto;
use egide_api::ServiceContext;

/// Builds and serves the gRPC server on `addr`, shutting down when `shutdown` resolves.
///
/// Registers tonic health (v1), gRPC reflection (v1), and all four Egide domain
/// services: Sys, Secrets, Transit, and ServiceToken. The health reporter marks
/// the Transit service as `SERVING` on startup; overall server health (`""`) is
/// set to `SERVING` by tonic-health by default.
pub async fn serve(
    state: Arc<ServiceContext>,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<proto::transit_service_server::TransitServiceServer<TransitGrpc>>()
        .await;

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(egide_api::proto::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(reflection)
        .add_service(proto::sys_service_server::SysServiceServer::new(SysGrpc {
            state: state.clone(),
        }))
        .add_service(proto::secrets_service_server::SecretsServiceServer::new(
            SecretsGrpc {
                state: state.clone(),
            },
        ))
        .add_service(proto::transit_service_server::TransitServiceServer::new(
            TransitGrpc {
                state: state.clone(),
            },
        ))
        .add_service(
            proto::service_token_service_server::ServiceTokenServiceServer::new(ServiceTokenGrpc {
                state,
            }),
        )
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn grpc_server_binds_and_shuts_down() {
        let (_tmp, ctx, _root) = tests_support::unsealed_context_with_token().await;

        let (tx, rx) = oneshot::channel::<()>();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Bind an ephemeral port and hand the actual address back via a channel.
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        drop(listener); // release so tonic can rebind

        let shutdown_fut = async move {
            let _ = rx.await;
        };

        let handle = tokio::spawn(serve(ctx, bound_addr, shutdown_fut));

        // Give the server a moment to start.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Trigger controlled shutdown.
        tx.send(()).unwrap();

        // The future must resolve without error within 2 s.
        let result = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("serve did not finish in time")
            .expect("tokio task panicked");

        assert!(result.is_ok(), "grpc::serve returned error: {result:?}");
    }
}
