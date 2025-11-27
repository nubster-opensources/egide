//! Egide Server - Main entry point.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use clap::Parser;
use serde::Serialize;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "egide-server")]
#[command(about = "Nubster Egide - Secrets, KMS, and PKI server")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config/egide.toml")]
    config: String,

    /// Enable development mode (auto-unseal, in-memory storage)
    #[arg(long, env = "EGIDE_DEV_MODE")]
    dev: bool,

    /// Server bind address
    #[arg(long, default_value = "0.0.0.0:8200", env = "EGIDE_BIND_ADDRESS")]
    bind: String,
}

/// Server state shared across handlers.
struct AppState {
    start_time: Instant,
    version: &'static str,
    sealed: bool,
    initialized: bool,
}

/// Health check response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    sealed: bool,
    initialized: bool,
    uptime_secs: u64,
}

/// Status response for detailed server info.
#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    sealed: bool,
    initialized: bool,
    cluster_name: Option<String>,
    cluster_id: Option<String>,
}

async fn health_handler(State(state): State<Arc<AppState>>) -> (StatusCode, Json<HealthResponse>) {
    let response = HealthResponse {
        status: "ok",
        version: state.version,
        sealed: state.sealed,
        initialized: state.initialized,
        uptime_secs: state.start_time.elapsed().as_secs(),
    };
    (StatusCode::OK, Json(response))
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: state.version,
        sealed: state.sealed,
        initialized: state.initialized,
        cluster_name: None,
        cluster_id: None,
    })
}

async fn root_handler() -> &'static str {
    "Egide - Secrets, KMS, and PKI Server"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    tracing::info!("Starting Egide server...");
    tracing::info!("Bind address: {}", cli.bind);

    if cli.dev {
        tracing::warn!("Development mode enabled - DO NOT USE IN PRODUCTION");
    }

    let state = Arc::new(AppState {
        start_time: Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
        sealed: !cli.dev,
        initialized: cli.dev,
    });

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/v1/sys/health", get(health_handler))
        .route("/v1/sys/status", get(status_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cli.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Egide server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Egide server stopped");

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    tracing::info!("Shutdown signal received");
}
