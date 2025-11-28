//! Egide CLI - Command line interface.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};

// ============================================================================
// CLI Structure
// ============================================================================

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
    /// Check server status
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
        /// Unseal key (or read from stdin if not provided)
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
        /// Output format (json, value)
        #[arg(long, default_value = "json")]
        format: String,
        /// Specific field to extract (only with format=value)
        #[arg(long)]
        field: Option<String>,
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
    List,
}

// ============================================================================
// API Types
// ============================================================================

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    sealed: bool,
    initialized: bool,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

#[derive(Debug, Deserialize)]
struct InitResponse {
    root_token: String,
    keys: Vec<String>,
    keys_base64: Vec<String>,
}

#[derive(Serialize)]
struct UnsealRequest {
    key: String,
}

#[derive(Debug, Deserialize)]
struct UnsealResponse {
    sealed: bool,
    threshold: u8,
    progress: u8,
}

#[derive(Debug, Deserialize)]
struct SealResponse {
    sealed: bool,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct SecretPutRequest {
    data: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SecretResponse {
    data: HashMap<String, String>,
    #[allow(dead_code)]
    metadata: SecretMetadata,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SecretMetadata {
    version: u32,
    created_at: u64,
    deleted: bool,
}

#[derive(Debug, Deserialize)]
struct SecretWriteResponse {
    version: u32,
}

#[derive(Debug, Deserialize)]
struct SecretListResponse {
    keys: Vec<String>,
}

// ============================================================================
// HTTP Client
// ============================================================================

struct EgideClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl EgideClient {
    fn new(base_url: &str, token: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn get_health(&self) -> Result<HealthResponse> {
        let resp = self
            .client
            .get(self.url("/v1/sys/health"))
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Server error: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn init(&self, shares: u8, threshold: u8) -> Result<InitResponse> {
        let req = InitRequest {
            secret_shares: shares,
            secret_threshold: threshold,
        };

        let resp = self
            .client
            .post(self.url("/v1/sys/init"))
            .json(&req)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Init failed: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn unseal(&self, key: &str) -> Result<UnsealResponse> {
        let req = UnsealRequest {
            key: key.to_string(),
        };

        let resp = self
            .client
            .post(self.url("/v1/sys/unseal"))
            .json(&req)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Unseal failed: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn seal(&self) -> Result<SealResponse> {
        let mut req = self.client.post(self.url("/v1/sys/seal"));

        if let Some(token) = &self.token {
            req = req.header("X-Egide-Token", token);
        }

        let resp = req.send().await.context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Seal failed: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn secret_get(&self, path: &str) -> Result<SecretResponse> {
        let token = self
            .token
            .as_ref()
            .context("Authentication token required. Set EGIDE_TOKEN or use --token")?;

        let resp = self
            .client
            .get(self.url(&format!("/v1/secrets/{}", path)))
            .header("X-Egide-Token", token)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Get secret failed: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn secret_put(
        &self,
        path: &str,
        data: HashMap<String, String>,
    ) -> Result<SecretWriteResponse> {
        let token = self
            .token
            .as_ref()
            .context("Authentication token required. Set EGIDE_TOKEN or use --token")?;

        let req = SecretPutRequest { data };

        let resp = self
            .client
            .put(self.url(&format!("/v1/secrets/{}", path)))
            .header("X-Egide-Token", token)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Put secret failed: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }

    async fn secret_delete(&self, path: &str) -> Result<()> {
        let token = self
            .token
            .as_ref()
            .context("Authentication token required. Set EGIDE_TOKEN or use --token")?;

        let resp = self
            .client
            .delete(self.url(&format!("/v1/secrets/{}", path)))
            .header("X-Egide-Token", token)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("Delete secret failed: {}", error.error);
        }

        Ok(())
    }

    async fn secret_list(&self) -> Result<SecretListResponse> {
        let token = self
            .token
            .as_ref()
            .context("Authentication token required. Set EGIDE_TOKEN or use --token")?;

        let resp = self
            .client
            .get(self.url("/v1/secrets"))
            .header("X-Egide-Token", token)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !resp.status().is_success() {
            let error: ErrorResponse = resp.json().await.unwrap_or(ErrorResponse {
                error: "Unknown error".into(),
            });
            bail!("List secrets failed: {}", error.error);
        }

        resp.json().await.context("Failed to parse response")
    }
}

// ============================================================================
// Command Handlers
// ============================================================================

async fn cmd_status(client: &EgideClient) -> Result<()> {
    let health = client.get_health().await?;

    println!("Egide server status:");
    println!("  Status:      {}", health.status);
    println!("  Version:     {}", health.version);
    println!("  Initialized: {}", health.initialized);
    println!("  Sealed:      {}", health.sealed);
    println!("  Uptime:      {}s", health.uptime_secs);

    Ok(())
}

async fn cmd_operator_init(client: &EgideClient, shares: u8, threshold: u8) -> Result<()> {
    println!(
        "Initializing Egide with {} shares, threshold {}...",
        shares, threshold
    );

    let result = client.init(shares, threshold).await?;

    println!();
    println!("Egide initialized successfully!");
    println!();
    println!("Unseal Keys (hex):");
    for (i, key) in result.keys.iter().enumerate() {
        println!("  Key {}: {}", i + 1, key);
    }
    println!();
    println!("Unseal Keys (base64):");
    for (i, key) in result.keys_base64.iter().enumerate() {
        println!("  Key {}: {}", i + 1, key);
    }
    println!();
    println!("Root Token: {}", result.root_token);
    println!();
    println!("IMPORTANT: Save these keys securely! They are required to unseal Egide.");
    println!("The root token is needed for administrative operations.");

    Ok(())
}

async fn cmd_operator_unseal(client: &EgideClient, key: Option<String>) -> Result<()> {
    let key = match key {
        Some(k) => k,
        None => {
            print!("Enter unseal key: ");
            io::stdout().flush()?;
            let stdin = io::stdin();
            let mut line = String::new();
            stdin.lock().read_line(&mut line)?;
            line.trim().to_string()
        },
    };

    if key.is_empty() {
        bail!("Unseal key cannot be empty");
    }

    let result = client.unseal(&key).await?;

    if result.sealed {
        println!(
            "Unseal progress: {}/{} keys provided",
            result.progress, result.threshold
        );
        println!("Egide is still sealed. Provide more keys to complete unseal.");
    } else {
        println!("Egide is now unsealed!");
    }

    Ok(())
}

async fn cmd_operator_seal(client: &EgideClient) -> Result<()> {
    let result = client.seal().await?;

    if result.sealed {
        println!("Egide is now sealed.");
    } else {
        println!("Warning: Seal operation returned but vault reports unsealed.");
    }

    Ok(())
}

async fn cmd_secrets_get(
    client: &EgideClient,
    path: &str,
    format: &str,
    field: Option<&str>,
) -> Result<()> {
    let secret = client.secret_get(path).await?;

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&secret.data)?);
        },
        "value" => {
            if let Some(field) = field {
                if let Some(value) = secret.data.get(field) {
                    println!("{}", value);
                } else {
                    bail!("Field '{}' not found in secret", field);
                }
            } else {
                for (k, v) in &secret.data {
                    println!("{}={}", k, v);
                }
            }
        },
        _ => bail!("Unknown format: {}. Use 'json' or 'value'", format),
    }

    Ok(())
}

async fn cmd_secrets_put(client: &EgideClient, path: &str, pairs: &[String]) -> Result<()> {
    let mut data = HashMap::new();

    for pair in pairs {
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() != 2 {
            bail!("Invalid key=value pair: {}. Use format: key=value", pair);
        }
        data.insert(parts[0].to_string(), parts[1].to_string());
    }

    let result = client.secret_put(path, data).await?;

    println!("Secret written successfully (version {})", result.version);

    Ok(())
}

async fn cmd_secrets_delete(client: &EgideClient, path: &str) -> Result<()> {
    client.secret_delete(path).await?;
    println!("Secret '{}' deleted", path);
    Ok(())
}

async fn cmd_secrets_list(client: &EgideClient) -> Result<()> {
    let result = client.secret_list().await?;

    if result.keys.is_empty() {
        println!("No secrets found");
    } else {
        println!("Secrets:");
        for key in &result.keys {
            println!("  {}", key);
        }
    }

    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = EgideClient::new(&cli.addr, cli.token)?;

    match cli.command {
        Commands::Status => cmd_status(&client).await,
        Commands::Operator { command } => match command {
            OperatorCommands::Init {
                key_shares,
                key_threshold,
            } => cmd_operator_init(&client, key_shares, key_threshold).await,
            OperatorCommands::Unseal { key } => cmd_operator_unseal(&client, key).await,
            OperatorCommands::Seal => cmd_operator_seal(&client).await,
        },
        Commands::Secrets { command } => match command {
            SecretsCommands::Get {
                path,
                format,
                field,
            } => cmd_secrets_get(&client, &path, &format, field.as_deref()).await,
            SecretsCommands::Put { path, data } => cmd_secrets_put(&client, &path, &data).await,
            SecretsCommands::Delete { path } => cmd_secrets_delete(&client, &path).await,
            SecretsCommands::List => cmd_secrets_list(&client).await,
        },
    }
}
