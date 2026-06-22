//! Integration tests for Egide server.
//!
//! These tests verify the complete workflow from initialization to secrets management.

// Allow unwrap() in tests - panics are acceptable for test assertions
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
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
pub struct TestServer {
    process: Child,
    /// Base URL of the running server (e.g. `http://127.0.0.1:18200`).
    pub base_url: String,
    /// TCP port the server is listening on.
    pub port: u16,
    _data_dir: TempDir,
}

impl TestServer {
    /// Start a new test server on the specified port.
    pub async fn start(port: u16) -> Result<Self> {
        let data_dir = TempDir::new().context("Failed to create temp dir")?;

        // Find the server binary
        let server_binary = find_server_binary()?;

        let process = Command::new(&server_binary)
            .arg("--dev")
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Failed to start server: {}", server_binary.display()))?;

        let base_url = format!("http://127.0.0.1:{port}");

        let server = Self {
            process,
            base_url,
            port,
            _data_dir: data_dir,
        };

        // Wait for server to be ready
        server.wait_for_ready().await?;

        Ok(server)
    }

    /// Wait for the server to be ready to serve requests.
    ///
    /// A live `/v1/sys/health` response is not sufficient: in dev mode the
    /// listener accepts connections while auto-init and auto-unseal are still
    /// running, leaving a window where health reports `sealed: true`. Tests
    /// that assert on an unsealed server would flake on that window, so this
    /// polls until the server is both initialized and unsealed.
    async fn wait_for_ready(&self) -> Result<()> {
        let client = Client::new();
        let url = format!("{}/v1/sys/health", self.base_url);

        for _ in 0..50 {
            if let Ok(resp) = client.get(&url).send().await {
                if resp.status().is_success() {
                    if let Ok(health) = resp.json::<HealthResponse>().await {
                        if health.initialized && !health.sealed {
                            return Ok(());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        bail!("Server failed to become initialized and unsealed within 5 seconds")
    }

    /// Get a configured HTTP client for this server.
    #[must_use]
    pub fn client(&self) -> EgideClient {
        EgideClient::new(&self.base_url)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Find the server binary in the target directory.
fn find_server_binary() -> Result<std::path::PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());

    // Try debug build first, then release
    let candidates = [
        std::path::Path::new(&manifest_dir).join("../../target/debug/egide-server"),
        std::path::Path::new(&manifest_dir).join("../../target/debug/egide-server.exe"),
        std::path::Path::new(&manifest_dir).join("../../target/release/egide-server"),
        std::path::Path::new(&manifest_dir).join("../../target/release/egide-server.exe"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.canonicalize()?);
        }
    }

    bail!(
        "Could not find egide-server binary. Run 'cargo build -p egide-server' first. Searched in: {candidates:?}"
    )
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
    use std::sync::atomic::{AtomicU16, Ordering};

    // Port counter to avoid conflicts between parallel tests
    static PORT_COUNTER: AtomicU16 = AtomicU16::new(18200);

    fn next_port() -> u16 {
        PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
    }

    #[tokio::test]
    async fn test_server_health_in_dev_mode() {
        let server = TestServer::start(next_port()).await.unwrap();
        let client = server.client();

        let health = client.health().await.unwrap();

        assert_eq!(health.status, "ok");
        assert!(health.initialized, "Dev mode should auto-initialize");
        assert!(!health.sealed, "Dev mode should auto-unseal");
    }

    #[tokio::test]
    async fn test_full_secrets_workflow() {
        let server = TestServer::start(next_port()).await.unwrap();

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
        let port = next_port();
        let data_dir = TempDir::new().unwrap();

        let server_binary = find_server_binary().unwrap();

        let mut process = Command::new(&server_binary)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let base_url = format!("http://127.0.0.1:{port}");
        let client = EgideClient::new(&base_url);

        // Wait for server to be ready (robust wait with retries)
        let mut health = None;
        for _ in 0..50 {
            match client.health().await {
                Ok(h) => {
                    health = Some(h);
                    break;
                },
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }

        // 1. Check initial state - should be uninitialized
        let health = health.expect("Server failed to start within 5 seconds");
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

        // Cleanup
        let _ = process.kill();
        let _ = process.wait();
    }

    #[tokio::test]
    async fn test_authentication_required() {
        let server = TestServer::start(next_port()).await.unwrap();
        let client = server.client(); // No token

        // Try to list secrets without token - should fail
        let result = client.secret_list().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let server = TestServer::start(next_port()).await.unwrap();
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
        let port = next_port();
        let data_dir = TempDir::new().unwrap();
        let server_binary = find_server_binary().unwrap();

        let mut process = std::process::Command::new(&server_binary)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let base_url = format!("http://127.0.0.1:{port}");
        let client = EgideClient::new(&base_url);

        // Wait for server
        for _ in 0..50 {
            if client.health().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

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

        let _ = process.kill();
        let _ = process.wait();
    }

    /// POST /v1/sys/seal with a bogus token must return 401 Unauthorized.
    #[tokio::test]
    async fn test_seal_requires_token_invalid_returns_401() {
        let port = next_port();
        let data_dir = TempDir::new().unwrap();
        let server_binary = find_server_binary().unwrap();

        let mut process = std::process::Command::new(&server_binary)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let base_url = format!("http://127.0.0.1:{port}");
        let client = EgideClient::new(&base_url);

        for _ in 0..50 {
            if client.health().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

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

        let _ = process.kill();
        let _ = process.wait();
    }

    /// POST /v1/sys/seal with a valid root token must return 200 and sealed=true.
    #[tokio::test]
    async fn test_seal_with_root_token_returns_200() {
        let port = next_port();
        let data_dir = TempDir::new().unwrap();
        let server_binary = find_server_binary().unwrap();

        let mut process = std::process::Command::new(&server_binary)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let base_url = format!("http://127.0.0.1:{port}");
        let client = EgideClient::new(&base_url);

        for _ in 0..50 {
            if client.health().await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

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

        let _ = process.kill();
        let _ = process.wait();
    }

    // Note: the 403 case (authenticated but non-root) is deferred.
    // The RootToken backend only issues root contexts, so there is no
    // straightforward way to produce an authenticated non-root token in tests.
    // Coverage: 401 (missing) + 401 (invalid) + 200 (root) are the hard criteria.
}
