//! Egide Server - Main entry point.

use clap::Parser;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
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

    // TODO: Initialize server
    // TODO: Start HTTP/gRPC listeners

    tracing::info!("Egide server started successfully");

    // Keep the server running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");

    Ok(())
}
