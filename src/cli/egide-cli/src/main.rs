//! Egide CLI - Command line interface.

use std::time::Duration;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "egide")]
#[command(about = "Nubster Egide CLI - Manage secrets, keys, and certificates")]
#[command(version)]
struct Cli {
    /// Egide server address
    #[arg(long, default_value = "http://localhost:8200", env = "EGIDE_ADDR")]
    addr: String,

    /// Authentication token
    #[arg(long, env = "EGIDE_TOKEN")]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Operator commands (init, seal, unseal)
    Operator {
        #[command(subcommand)]
        command: OperatorCommands,
    },
    /// Secrets management
    Secrets {
        #[command(subcommand)]
        command: SecretsCommands,
    },
    /// Transit encryption
    Transit {
        #[command(subcommand)]
        command: TransitCommands,
    },
    /// KMS operations
    Kms {
        #[command(subcommand)]
        command: KmsCommands,
    },
    /// PKI operations
    Pki {
        #[command(subcommand)]
        command: PkiCommands,
    },
    /// Check server status (used for health checks)
    Status,
}

#[derive(Subcommand)]
enum OperatorCommands {
    /// Initialize a new Egide server
    Init {
        /// Number of key shares
        #[arg(long, default_value = "5")]
        key_shares: u8,
        /// Key threshold required to unseal
        #[arg(long, default_value = "3")]
        key_threshold: u8,
    },
    /// Unseal the server
    Unseal {
        /// Unseal key
        key: Option<String>,
    },
    /// Seal the server
    Seal,
}

#[derive(Subcommand)]
enum SecretsCommands {
    /// Get a secret
    Get {
        /// Secret path
        path: String,
    },
    /// Store a secret
    Put {
        /// Secret path
        path: String,
        /// Key=value pairs
        #[arg(required = true)]
        data: Vec<String>,
    },
    /// Delete a secret
    Delete {
        /// Secret path
        path: String,
    },
    /// List secrets
    List {
        /// Path prefix
        #[arg(default_value = "")]
        prefix: String,
    },
}

#[derive(Subcommand)]
enum TransitCommands {
    /// Encrypt data
    Encrypt {
        /// Key name
        key: String,
        /// Plaintext (or read from stdin)
        plaintext: Option<String>,
    },
    /// Decrypt data
    Decrypt {
        /// Key name
        key: String,
        /// Ciphertext
        ciphertext: String,
    },
}

#[derive(Subcommand)]
enum KmsCommands {
    /// Create a new key
    Create {
        /// Key name
        name: String,
        /// Key type (aes256, rsa2048, rsa4096, ecdsa-p256, ed25519)
        #[arg(long, default_value = "aes256")]
        key_type: String,
    },
    /// List keys
    List,
    /// Rotate a key
    Rotate {
        /// Key name
        name: String,
    },
}

#[derive(Subcommand)]
enum PkiCommands {
    /// Initialize CA
    InitCa {
        /// Common name
        #[arg(long)]
        cn: String,
        /// Organization
        #[arg(long)]
        org: Option<String>,
    },
    /// Issue a certificate
    Issue {
        /// Common name
        #[arg(long)]
        cn: String,
        /// Template name
        #[arg(long, default_value = "server")]
        template: String,
    },
    /// List certificates
    List,
}

/// Health response from server.
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    sealed: bool,
    initialized: bool,
    uptime_secs: u64,
}

/// Check server health by calling the /v1/sys/health endpoint.
async fn check_status(addr: &str) -> anyhow::Result<HealthResponse> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("Failed to create HTTP client")?;

    let url = format!("{}/v1/sys/health", addr.trim_end_matches('/'));

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("Failed to connect to Egide server at {}", addr))?;

    if !response.status().is_success() {
        bail!(
            "Server returned error status: {} {}",
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("Unknown")
        );
    }

    let health: HealthResponse = response
        .json()
        .await
        .context("Failed to parse health response")?;

    Ok(health)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Status => match check_status(&cli.addr).await {
            Ok(health) => {
                println!("Egide server at {} is healthy", cli.addr);
                println!("  Status:      {}", health.status);
                println!("  Version:     {}", health.version);
                println!("  Initialized: {}", health.initialized);
                println!("  Sealed:      {}", health.sealed);
                println!("  Uptime:      {}s", health.uptime_secs);
                Ok(())
            },
            Err(e) => {
                eprintln!("Egide server at {} is unhealthy: {}", cli.addr, e);
                std::process::exit(1);
            },
        },
        Commands::Operator { command } => {
            match command {
                OperatorCommands::Init {
                    key_shares,
                    key_threshold,
                } => {
                    println!(
                        "Initializing Egide with {} shares, threshold {}...",
                        key_shares, key_threshold
                    );
                    // TODO: Implement init
                    Ok(())
                },
                OperatorCommands::Unseal { key: _key } => {
                    println!("Unsealing Egide...");
                    // TODO: Implement unseal
                    Ok(())
                },
                OperatorCommands::Seal => {
                    println!("Sealing Egide...");
                    // TODO: Implement seal
                    Ok(())
                },
            }
        },
        Commands::Secrets { command } => {
            match command {
                SecretsCommands::Get { path } => {
                    println!("Getting secret: {}", path);
                    // TODO: Implement get
                    Ok(())
                },
                SecretsCommands::Put { path, data: _data } => {
                    println!("Storing secret: {}", path);
                    // TODO: Implement put
                    Ok(())
                },
                SecretsCommands::Delete { path } => {
                    println!("Deleting secret: {}", path);
                    // TODO: Implement delete
                    Ok(())
                },
                SecretsCommands::List { prefix } => {
                    println!("Listing secrets with prefix: {}", prefix);
                    // TODO: Implement list
                    Ok(())
                },
            }
        },
        Commands::Transit { command } => {
            match command {
                TransitCommands::Encrypt {
                    key,
                    plaintext: _plaintext,
                } => {
                    println!("Encrypting with key: {}", key);
                    // TODO: Implement encrypt
                    Ok(())
                },
                TransitCommands::Decrypt {
                    key,
                    ciphertext: _ciphertext,
                } => {
                    println!("Decrypting with key: {}", key);
                    // TODO: Implement decrypt
                    Ok(())
                },
            }
        },
        Commands::Kms { command } => {
            match command {
                KmsCommands::Create { name, key_type } => {
                    println!("Creating key {} of type {}", name, key_type);
                    // TODO: Implement create
                    Ok(())
                },
                KmsCommands::List => {
                    println!("Listing keys...");
                    // TODO: Implement list
                    Ok(())
                },
                KmsCommands::Rotate { name } => {
                    println!("Rotating key: {}", name);
                    // TODO: Implement rotate
                    Ok(())
                },
            }
        },
        Commands::Pki { command } => {
            match command {
                PkiCommands::InitCa { cn, org: _org } => {
                    println!("Initializing CA with CN: {}", cn);
                    // TODO: Implement init-ca
                    Ok(())
                },
                PkiCommands::Issue {
                    cn,
                    template: _template,
                } => {
                    println!("Issuing certificate for: {}", cn);
                    // TODO: Implement issue
                    Ok(())
                },
                PkiCommands::List => {
                    println!("Listing certificates...");
                    // TODO: Implement list
                    Ok(())
                },
            }
        },
    }
}
