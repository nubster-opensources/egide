//! Entry point for the egide-server binary.
use clap::Parser;
use egide_server::{run, Cli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Cli::parse()).await
}
