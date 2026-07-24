//! Integration tests for Egide server.
//!
//! These tests verify the complete workflow from initialization to secrets management.

// Allow unwrap() in tests - panics are acceptable for test assertions
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
#[cfg(test)]
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tempfile::TempDir;

// ============================================================================
// API Types
// ============================================================================

/// Response body from `GET /v1/sys/health`.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    /// Current status of the server (e.g. "ok").
    pub status: String,
    /// Server version string.
    pub version: String,
    /// Whether the vault has been initialized.
    pub initialized: bool,
    /// Whether the vault is currently sealed.
    pub sealed: bool,
}

/// Request body for `POST /v1/sys/init`.
#[derive(Debug, Serialize)]
pub struct InitRequest {
    /// Number of key shares to generate.
    pub secret_shares: u8,
    /// Minimum shares required to unseal.
    pub secret_threshold: u8,
}

/// Response body from `POST /v1/sys/init`.
#[derive(Debug, Deserialize)]
pub struct InitResponse {
    /// Root token granting full access.
    pub root_token: String,
    /// Shamir key shares (hex-encoded).
    pub keys: Vec<String>,
}

/// Request body for `POST /v1/sys/unseal`.
#[derive(Debug, Serialize)]
pub struct UnsealRequest {
    /// A single Shamir key share (hex-encoded).
    pub key: String,
}

/// Response body from `POST /v1/sys/unseal`.
#[derive(Debug, Deserialize)]
pub struct UnsealResponse {
    /// Whether the vault is still sealed after this operation.
    pub sealed: bool,
    /// Number of shares required to unseal.
    pub threshold: u8,
    /// Number of shares received so far.
    pub progress: u8,
}

/// Request body for `PUT /v1/secrets/{path}`.
#[derive(Debug, Serialize)]
pub struct SecretPutRequest {
    /// Key-value pairs to store at the given path.
    pub data: HashMap<String, String>,
}

/// Response body from `GET /v1/secrets/{path}`.
#[derive(Debug, Deserialize)]
pub struct SecretResponse {
    /// Key-value pairs stored at the requested path.
    pub data: HashMap<String, String>,
}

/// Response body from `PUT /v1/secrets/{path}`.
#[derive(Debug, Deserialize)]
pub struct SecretWriteResponse {
    /// Version number after the write.
    pub version: u32,
}

/// Response body from `GET /v1/secrets` (list).
#[derive(Debug, Deserialize)]
pub struct SecretListResponse {
    /// Secret paths available to the caller.
    pub keys: Vec<String>,
}

/// Response body from `POST /v1/sys/seal`.
#[derive(Debug, Deserialize)]
pub struct SealResponse {
    /// Whether the vault is sealed after this operation.
    pub sealed: bool,
}

// ============================================================================
// Test Server
// ============================================================================

/// A test server instance that manages its own data directory and process.
///
/// Only available under `cfg(test)`: it is built through `server_binary()`,
/// which links `escargot` (a dev-dependency, unavailable in a plain library
/// build).
#[cfg(test)]
pub struct TestServer {
    _process: tokio::process::Child,
    /// Base URL of the running server (e.g. `http://127.0.0.1:53312`).
    pub base_url: String,
    /// TCP port the server is listening on.
    pub port: u16,
    _data_dir: TempDir,
}

#[cfg(test)]
impl TestServer {
    /// Start a dev-mode server (auto-init and auto-unseal), ready to serve.
    pub async fn start_dev() -> Result<Self> {
        Self::spawn(true).await
    }

    /// Start a server without dev mode, for the explicit init/unseal flow.
    pub async fn start_manual() -> Result<Self> {
        Self::spawn(false).await
    }

    async fn spawn(dev: bool) -> Result<Self> {
        use tokio::io::{AsyncBufReadExt, BufReader};

        let data_dir = TempDir::new().context("Failed to create temp dir")?;
        let mut command = tokio::process::Command::new(server_binary());
        if dev {
            command.arg("--dev").env("EGIDE_UNSAFE_DEV_MODE", "1");
        }
        let mut process = command
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--grpc-bind")
            .arg("127.0.0.1:0")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to start server")?;

        let stdout = process.stdout.take().context("child stdout missing")?;
        let mut reader = BufReader::new(stdout).lines();
        let addr = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(line) = reader.next_line().await? {
                if let Some(rest) = line.strip_prefix("EGIDE_LISTEN_ADDR=") {
                    return Ok::<_, anyhow::Error>(rest.to_string());
                }
            }
            bail!("server exited before announcing its address")
        })
        .await
        .context("timed out waiting for EGIDE_LISTEN_ADDR")??;

        let socket: SocketAddr = addr.parse().context("invalid announced address")?;
        let base_url = format!("http://{socket}");
        let server = Self {
            _process: process,
            base_url,
            port: socket.port(),
            _data_dir: data_dir,
        };
        server.wait_for_ready(dev).await?;
        Ok(server)
    }

    /// Wait until the server is reachable. In dev mode, also wait until it is
    /// initialized and unsealed.
    async fn wait_for_ready(&self, dev: bool) -> Result<()> {
        let client = Client::new();
        let url = format!("{}/v1/sys/health", self.base_url);
        for _ in 0..50 {
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    if !dev {
                        return Ok(());
                    }
                    if let Ok(health) = resp.json::<HealthResponse>().await {
                        if health.initialized && !health.sealed {
                            return Ok(());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("Server did not become ready within 5 seconds")
    }

    /// Get a configured HTTP client for this server.
    #[must_use]
    pub fn client(&self) -> EgideClient {
        EgideClient::new(&self.base_url)
    }
}

/// Builds `egide-server` once and returns the cached binary path.
#[cfg(test)]
fn server_binary() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        escargot::CargoBuild::new()
            .package("egide-server")
            .bin("egide-server")
            .run()
            .expect("failed to build egide-server")
            .path()
            .to_path_buf()
    })
}

/// Builds `egide` (the CLI) once and returns the cached binary path.
#[cfg(test)]
fn cli_binary() -> &'static Path {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        escargot::CargoBuild::new()
            .package("egide-cli")
            .bin("egide")
            .run()
            .expect("failed to build egide")
            .path()
            .to_path_buf()
    })
}

// ============================================================================
// Test Client
// ============================================================================

/// HTTP client for testing the Egide API.
pub struct EgideClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl EgideClient {
    /// Creates a new client targeting the given base URL.
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            base_url: base_url.to_string(),
            token: None,
        }
    }

    /// Returns a new client with the given bearer token set.
    #[must_use]
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Calls `GET /v1/sys/health` and returns the parsed response.
    pub async fn health(&self) -> Result<HealthResponse> {
        let resp = self.client.get(self.url("/v1/sys/health")).send().await?;
        Ok(resp.json().await?)
    }

    /// Calls `POST /v1/sys/init` to initialize the vault with Shamir parameters.
    pub async fn init(&self, shares: u8, threshold: u8) -> Result<InitResponse> {
        let req = InitRequest {
            secret_shares: shares,
            secret_threshold: threshold,
        };
        let resp = self
            .client
            .post(self.url("/v1/sys/init"))
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("Init failed: {}", resp.text().await?);
        }
        Ok(resp.json().await?)
    }

    /// Calls `POST /v1/sys/unseal` with one Shamir key share.
    pub async fn unseal(&self, key: &str) -> Result<UnsealResponse> {
        let req = UnsealRequest {
            key: key.to_string(),
        };
        let resp = self
            .client
            .post(self.url("/v1/sys/unseal"))
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("Unseal failed: {}", resp.text().await?);
        }
        Ok(resp.json().await?)
    }

    /// Calls `POST /v1/sys/seal` to seal the vault.
    pub async fn seal(&self) -> Result<()> {
        let mut req = self.client.post(self.url("/v1/sys/seal"));
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            bail!("Seal failed: {}", resp.text().await?);
        }
        Ok(())
    }

    /// Posts to `/v1/sys/seal` and returns the raw HTTP status code.
    ///
    /// Used in authentication tests to assert 401/403 without panicking.
    pub async fn seal_raw(&self) -> Result<u16> {
        let mut req = self.client.post(self.url("/v1/sys/seal"));
        if let Some(token) = &self.token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        let resp = req.send().await?;
        Ok(resp.status().as_u16())
    }

    /// Posts to `/v1/sys/seal` with an explicit token override and returns the raw HTTP status code.
    pub async fn seal_raw_with_token(&self, token: &str) -> Result<u16> {
        let resp = self
            .client
            .post(self.url("/v1/sys/seal"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
        Ok(resp.status().as_u16())
    }

    /// Calls `PUT /v1/secrets/{path}` to store key-value data.
    pub async fn secret_put(
        &self,
        path: &str,
        data: HashMap<String, String>,
    ) -> Result<SecretWriteResponse> {
        let token = self.token.as_ref().context("Token required")?;
        let req = SecretPutRequest { data };
        let resp = self
            .client
            .put(self.url(&format!("/v1/secrets/{path}")))
            .header("Authorization", format!("Bearer {token}"))
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("Put secret failed: {}", resp.text().await?);
        }
        Ok(resp.json().await?)
    }

    /// Calls `GET /v1/secrets/{path}` to retrieve stored key-value data.
    pub async fn secret_get(&self, path: &str) -> Result<SecretResponse> {
        let token = self.token.as_ref().context("Token required")?;
        let resp = self
            .client
            .get(self.url(&format!("/v1/secrets/{path}")))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("Get secret failed: {}", resp.text().await?);
        }
        Ok(resp.json().await?)
    }

    /// Calls `DELETE /v1/secrets/{path}` to remove a secret.
    pub async fn secret_delete(&self, path: &str) -> Result<()> {
        let token = self.token.as_ref().context("Token required")?;
        let resp = self
            .client
            .delete(self.url(&format!("/v1/secrets/{path}")))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("Delete secret failed: {}", resp.text().await?);
        }
        Ok(())
    }

    /// Calls `GET /v1/secrets` to list available secret paths.
    pub async fn secret_list(&self) -> Result<SecretListResponse> {
        let token = self.token.as_ref().context("Token required")?;
        let resp = self
            .client
            .get(self.url("/v1/secrets"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await?;
        if !resp.status().is_success() {
            bail!("List secrets failed: {}", resp.text().await?);
        }
        Ok(resp.json().await?)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dev_fixture_is_ready_and_unique_port() {
        let a = TestServer::start_dev().await.unwrap();
        let b = TestServer::start_dev().await.unwrap();
        assert_ne!(
            a.port, b.port,
            "each dev server must bind a distinct ephemeral port"
        );
        assert!(a.client().health().await.unwrap().initialized);
    }

    #[test]
    fn server_binary_is_built_and_exists() {
        let path = server_binary();
        assert!(path.exists(), "server binary should exist at {path:?}");
    }

    #[tokio::test]
    async fn test_server_health_in_dev_mode() {
        let server = TestServer::start_dev().await.unwrap();
        let client = server.client();

        let health = client.health().await.unwrap();

        assert_eq!(health.status, "ok");
        assert!(health.initialized, "Dev mode should auto-initialize");
        assert!(!health.sealed, "Dev mode should auto-unseal");
    }

    #[tokio::test]
    async fn test_full_secrets_workflow() {
        let server = TestServer::start_dev().await.unwrap();

        // In dev mode, we need to get the root token from the server logs
        // For now, we'll use the dev mode behavior where it's already unsealed
        // and we can use any token format for testing

        // Get health to confirm server is ready
        let client = server.client();
        let health = client.health().await.unwrap();
        assert!(!health.sealed);

        // We need to initialize fresh to get a token (dev mode already initialized)
        // For this test, let's start a non-dev server instead
        // Actually, in dev mode, the token is printed to logs
        // Let's create a helper that parses the token from server output
    }

    #[tokio::test]
    async fn test_complete_lifecycle_manual_init() {
        // Start server without dev mode to test full init flow
        let server = TestServer::start_manual().await.unwrap();
        let client = server.client();

        // 1. Check initial state - should be uninitialized
        let health = client.health().await.unwrap();
        assert!(!health.initialized, "Should not be initialized yet");
        assert!(health.sealed, "Should be sealed");

        // 2. Initialize with 3 shares, threshold 2
        let init_result = client.init(3, 2).await.unwrap();
        assert!(!init_result.root_token.is_empty());
        assert_eq!(init_result.keys.len(), 3);

        // 3. Verify still sealed after init
        let health = client.health().await.unwrap();
        assert!(health.initialized);
        assert!(health.sealed);

        // 4. Unseal with first key
        let unseal1 = client.unseal(&init_result.keys[0]).await.unwrap();
        assert!(unseal1.sealed); // Still sealed, need 2 keys
        assert_eq!(unseal1.progress, 1);
        assert_eq!(unseal1.threshold, 2);

        // 5. Unseal with second key
        let unseal2 = client.unseal(&init_result.keys[1]).await.unwrap();
        assert!(!unseal2.sealed); // Now unsealed!

        // 6. Verify unsealed
        let health = client.health().await.unwrap();
        assert!(!health.sealed);

        // 7. Create a secret
        let client = client.with_token(&init_result.root_token);
        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "super-secret".to_string());

        let write_result = client.secret_put("myapp/database", data).await.unwrap();
        assert_eq!(write_result.version, 1);

        // 8. Read the secret back
        let secret = client.secret_get("myapp/database").await.unwrap();
        assert_eq!(secret.data.get("username").unwrap(), "admin");
        assert_eq!(secret.data.get("password").unwrap(), "super-secret");

        // 9. List secrets
        let list = client.secret_list().await.unwrap();
        assert!(list.keys.contains(&"myapp/database".to_string()));

        // 10. Update the secret
        let mut updated_data = HashMap::new();
        updated_data.insert("username".to_string(), "admin".to_string());
        updated_data.insert("password".to_string(), "new-password".to_string());

        let write_result = client
            .secret_put("myapp/database", updated_data)
            .await
            .unwrap();
        assert_eq!(write_result.version, 2);

        // 11. Verify update
        let secret = client.secret_get("myapp/database").await.unwrap();
        assert_eq!(secret.data.get("password").unwrap(), "new-password");

        // 12. Delete the secret
        client.secret_delete("myapp/database").await.unwrap();

        // 13. Verify deleted (should fail)
        let result = client.secret_get("myapp/database").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authentication_required() {
        let server = TestServer::start_dev().await.unwrap();
        let client = server.client(); // No token

        // Try to list secrets without token - should fail
        let result = client.secret_list().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let server = TestServer::start_dev().await.unwrap();
        let client = server.client().with_token("invalid-token");

        // Try to list secrets with invalid token - should fail
        let result = client.secret_list().await;
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // seal authentication tests (issue #7)
    // -------------------------------------------------------------------------

    /// POST /v1/sys/seal without any token must return 401 Unauthorized.
    ///
    /// Before the fix this endpoint has no authentication, so it returns 200.
    /// The test documents the expected behaviour and will be RED until the fix
    /// is applied to `seal_handler`.
    #[tokio::test]
    async fn test_seal_requires_token_missing_returns_401() {
        let server = TestServer::start_manual().await.unwrap();
        let client = server.client();

        // Initialize and unseal so the vault is in Unsealed state
        let init = client.init(3, 2).await.unwrap();
        client.unseal(&init.keys[0]).await.unwrap();
        client.unseal(&init.keys[1]).await.unwrap();

        // No token: expect 401
        let status = client.seal_raw().await.unwrap();
        assert_eq!(
            status, 401,
            "seal without token must return 401, got {status}"
        );
    }

    /// POST /v1/sys/seal with a bogus token must return 401 Unauthorized.
    #[tokio::test]
    async fn test_seal_requires_token_invalid_returns_401() {
        let server = TestServer::start_manual().await.unwrap();
        let client = server.client();

        let init = client.init(3, 2).await.unwrap();
        client.unseal(&init.keys[0]).await.unwrap();
        client.unseal(&init.keys[1]).await.unwrap();

        // Bogus token: expect 401
        let status = client
            .seal_raw_with_token("this-is-not-a-valid-token")
            .await
            .unwrap();
        assert_eq!(
            status, 401,
            "seal with invalid token must return 401, got {status}"
        );
    }

    /// POST /v1/sys/seal with a valid root token must return 200 and sealed=true.
    #[tokio::test]
    async fn test_seal_with_root_token_returns_200() {
        let server = TestServer::start_manual().await.unwrap();
        let client = server.client();

        let init = client.init(3, 2).await.unwrap();
        client.unseal(&init.keys[0]).await.unwrap();
        client.unseal(&init.keys[1]).await.unwrap();

        // Root token: expect 200
        let authed_client = client.with_token(&init.root_token);
        let status = authed_client.seal_raw().await.unwrap();
        assert_eq!(
            status, 200,
            "seal with root token must return 200, got {status}"
        );
    }

    // Note: the 403 case (authenticated but non-root) is deferred.
    // The RootToken backend only issues root contexts, so there is no
    // straightforward way to produce an authenticated non-root token in tests.
    // Coverage: 401 (missing) + 401 (invalid) + 200 (root) are the hard criteria.

    // -------------------------------------------------------------------------
    // stdout port announcement tests (issue #97)
    // -------------------------------------------------------------------------

    /// On startup, the server must print exactly one `EGIDE_LISTEN_ADDR=<ip>:<port>`
    /// line to stdout, carrying the real bound port (not the requested `:0`).
    #[tokio::test]
    async fn server_announces_real_port_on_stdout() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let data_dir = TempDir::new().unwrap();
        let mut child = tokio::process::Command::new(server_binary())
            .arg("--dev")
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg("127.0.0.1:0")
            .arg("--grpc-bind")
            .arg("127.0.0.1:0")
            .env("EGIDE_UNSAFE_DEV_MODE", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        // Bounded read: if the announcement ever regresses, the child keeps its
        // stdout open and `next_line` would block forever. The timeout turns
        // that into a clean, fast failure instead of a hung test.
        let addr = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(rest) = line.strip_prefix("EGIDE_LISTEN_ADDR=") {
                    return rest.to_string();
                }
            }
            panic!("server closed stdout before announcing EGIDE_LISTEN_ADDR");
        })
        .await
        .expect("timed out waiting for EGIDE_LISTEN_ADDR announcement");
        assert!(
            !addr.ends_with(":0"),
            "announced port must be the real ephemeral port, got {addr}"
        );
    }

    // -------------------------------------------------------------------------
    // CLI authentication tests (issue #63)
    // -------------------------------------------------------------------------

    /// The `egide secrets put` / `egide secrets get` commands must authenticate
    /// against the server using the `Authorization: Bearer <token>` header.
    ///
    /// Before the fix, the CLI sends the token in a non-standard header that
    /// the server never reads, so both commands fail with a 401 from the
    /// server and a non-zero CLI exit code. This test drives the real `egide`
    /// binary as a subprocess
    /// against a real `egide-server` instance, so it proves the wire protocol
    /// end to end rather than only the internal header-building code.
    #[tokio::test]
    async fn cli_secrets_roundtrip_authenticates_with_bearer() {
        let cli_binary = cli_binary();
        let server = TestServer::start_manual().await.unwrap();
        let client = server.client();

        // Initialize and unseal through the REST helpers to obtain a root token.
        let init = client.init(3, 2).await.unwrap();
        client.unseal(&init.keys[0]).await.unwrap();
        client.unseal(&init.keys[1]).await.unwrap();

        let addr = server.base_url.clone();
        let token = init.root_token.clone();

        // `egide secrets put <path> <key>=<value>` should succeed and
        // authenticate with the root token via EGIDE_TOKEN.
        let put_output = Command::new(cli_binary)
            .arg("secrets")
            .arg("put")
            .arg("cli-roundtrip/config")
            .arg("greeting=hello-from-cli")
            .env("EGIDE_ADDR", &addr)
            .env("EGIDE_TOKEN", &token)
            .output()
            .unwrap();

        assert!(
            put_output.status.success(),
            "egide secrets put failed (status {:?}).\nstdout:\n{}\nstderr:\n{}",
            put_output.status.code(),
            String::from_utf8_lossy(&put_output.stdout),
            String::from_utf8_lossy(&put_output.stderr)
        );

        // `egide secrets get <path>` should succeed and return the stored value.
        let get_output = Command::new(cli_binary)
            .arg("secrets")
            .arg("get")
            .arg("cli-roundtrip/config")
            .env("EGIDE_ADDR", &addr)
            .env("EGIDE_TOKEN", &token)
            .output()
            .unwrap();

        assert!(
            get_output.status.success(),
            "egide secrets get failed (status {:?}).\nstdout:\n{}\nstderr:\n{}",
            get_output.status.code(),
            String::from_utf8_lossy(&get_output.stdout),
            String::from_utf8_lossy(&get_output.stderr)
        );

        let get_stdout = String::from_utf8_lossy(&get_output.stdout);
        assert!(
            get_stdout.contains("hello-from-cli"),
            "expected the stored value in `egide secrets get` output, got:\nstdout:\n{}\nstderr:\n{}",
            get_stdout,
            String::from_utf8_lossy(&get_output.stderr)
        );
    }
}
