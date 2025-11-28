//! Egide Server - Main entry point.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use async_trait::async_trait;
use egide_auth::{
    AuthBackend, AuthContext, AuthError, NubsterIdentityBackend, NubsterIdentityConfig,
    RootTokenBackend,
};
use egide_seal::{SealManager, SealStatus, ShamirConfig, Share};
use egide_secrets::SecretsEngine;

// ============================================================================
// Authentication Service
// ============================================================================

/// Header name for the authentication token.
const AUTH_HEADER: &str = "X-Egide-Token";

/// Combined authentication service that tries multiple backends.
pub struct AuthService {
    backends: Vec<Box<dyn AuthBackend>>,
}

impl AuthService {
    /// Creates a new auth service with the given backends.
    pub fn new(backends: Vec<Box<dyn AuthBackend>>) -> Self {
        Self { backends }
    }

    /// Validates a token against all configured backends.
    pub async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        for backend in &self.backends {
            match backend.validate(token).await {
                Ok(ctx) => {
                    tracing::debug!(backend = backend.name(), account = %ctx.account_id, "Auth success");
                    return Ok(ctx);
                },
                Err(AuthError::TokenExpired) => {
                    // Token expired is a definitive error, don't try other backends
                    return Err(AuthError::TokenExpired);
                },
                Err(_) => {
                    // Try next backend
                    continue;
                },
            }
        }
        Err(AuthError::InvalidCredentials)
    }
}

#[async_trait]
impl AuthBackend for AuthService {
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        AuthService::validate(self, token).await
    }

    fn name(&self) -> &'static str {
        "auth-service"
    }
}

/// Authenticated request extractor.
///
/// Validates the X-Egide-Token header and returns the authentication context.
pub struct Authenticated(pub AuthContext);

impl FromRequestParts<Arc<AppState>> for Authenticated {
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Extract token from header
        let token = parts
            .headers
            .get(AUTH_HEADER)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "missing authentication token".into(),
                    }),
                )
            })?;

        // Validate via auth service
        let ctx = state.auth.validate(token).await.map_err(|e| {
            let (status, message) = match e {
                AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "token expired"),
                AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid credentials"),
                AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "missing token"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "authentication failed"),
            };
            (
                status,
                Json(ErrorResponse {
                    error: message.into(),
                }),
            )
        })?;

        Ok(Authenticated(ctx))
    }
}

// ============================================================================
// CLI Arguments
// ============================================================================

/// Authentication backend type.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum AuthBackendType {
    /// Nubster.Identity JWT validation (for Cloud and Workspace OnPrem).
    NubsterIdentity,
    /// Root token validation (for dev mode and Standalone OnPrem).
    #[default]
    RootToken,
}

#[derive(Parser)]
#[command(name = "egide-server")]
#[command(about = "Nubster Egide - Secrets management server")]
#[command(version)]
struct Cli {
    /// Data directory for persistent storage.
    #[arg(long, default_value = "./data", env = "EGIDE_DATA_DIR")]
    data_dir: PathBuf,

    /// Enable development mode (auto-unseal, NOT FOR PRODUCTION).
    #[arg(long, env = "EGIDE_DEV_MODE")]
    dev: bool,

    /// Server bind address.
    #[arg(long, default_value = "0.0.0.0:8200", env = "EGIDE_BIND_ADDRESS")]
    bind: String,

    /// Authentication backend to use.
    #[arg(
        long,
        value_enum,
        default_value = "root-token",
        env = "EGIDE_AUTH_BACKEND"
    )]
    auth_backend: AuthBackendType,

    /// Nubster.Identity JWT secret (required for nubster-identity backend).
    #[arg(long, env = "EGIDE_IDENTITY_JWT_SECRET")]
    identity_jwt_secret: Option<String>,

    /// Nubster.Identity issuer URL.
    #[arg(
        long,
        default_value = "https://api.nubster.com",
        env = "EGIDE_IDENTITY_ISSUER"
    )]
    identity_issuer: String,

    /// Nubster.Identity audience.
    #[arg(long, default_value = "egide", env = "EGIDE_IDENTITY_AUDIENCE")]
    identity_audience: String,
}

// ============================================================================
// Application State
// ============================================================================

/// Shared application state.
pub struct AppState {
    /// Authentication service.
    pub auth: AuthService,
    /// Seal manager (handles init/seal/unseal).
    pub seal: RwLock<SealManager>,
    /// Secrets engine (available only when unsealed).
    pub secrets: RwLock<Option<SecretsEngine>>,
    /// Data directory path.
    pub data_dir: PathBuf,
    /// Server start time.
    pub start_time: Instant,
    /// Server version.
    pub version: &'static str,
}

impl AppState {
    /// Creates the secrets engine if unsealed.
    pub async fn ensure_secrets_engine(&self) -> Result<(), String> {
        let seal = self.seal.read().await;
        if seal.status() != SealStatus::Unsealed {
            return Err("Vault is sealed".into());
        }

        let master_key = seal
            .master_key()
            .ok_or_else(|| "Master key not available".to_string())?;

        let mut secrets = self.secrets.write().await;
        if secrets.is_none() {
            // Use "default" tenant for v0.1
            let engine = SecretsEngine::new(&self.data_dir, "default", master_key.clone())
                .await
                .map_err(|e| e.to_string())?;
            *secrets = Some(engine);
            tracing::info!("Secrets engine initialized");
        }
        Ok(())
    }

    /// Clears the secrets engine (called on seal).
    pub async fn clear_secrets_engine(&self) {
        let mut secrets = self.secrets.write().await;
        *secrets = None;
        tracing::info!("Secrets engine cleared");
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    initialized: bool,
    sealed: bool,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    initialized: bool,
    sealed: bool,
}

#[derive(Deserialize)]
struct InitRequest {
    #[serde(default = "default_shares")]
    secret_shares: u8,
    #[serde(default = "default_threshold")]
    secret_threshold: u8,
}

fn default_shares() -> u8 {
    5
}
fn default_threshold() -> u8 {
    3
}

#[derive(Serialize)]
struct InitResponse {
    root_token: String,
    keys: Vec<String>,
    keys_base64: Vec<String>,
}

#[derive(Deserialize)]
struct UnsealRequest {
    key: String,
}

#[derive(Serialize)]
struct UnsealResponse {
    sealed: bool,
    threshold: u8,
    progress: u8,
}

#[derive(Serialize)]
struct SealResponse {
    sealed: bool,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

// Secrets types
#[derive(Deserialize)]
struct SecretPutRequest {
    data: std::collections::HashMap<String, String>,
    #[serde(default)]
    cas: Option<u32>,
}

#[derive(Serialize)]
struct SecretResponse {
    data: std::collections::HashMap<String, String>,
    metadata: SecretMetadataResponse,
}

#[derive(Serialize)]
struct SecretMetadataResponse {
    version: u32,
    created_at: u64,
    deleted: bool,
}

#[derive(Serialize)]
struct SecretWriteResponse {
    version: u32,
}

#[derive(Serialize)]
struct SecretListResponse {
    keys: Vec<String>,
}

// ============================================================================
// Handlers - System
// ============================================================================

async fn root_handler() -> &'static str {
    "Egide - Secrets Management Server"
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let seal = state.seal.read().await;
    let status = seal.status();

    Json(HealthResponse {
        status: "ok",
        version: state.version,
        initialized: status != SealStatus::Uninitialized,
        sealed: status != SealStatus::Unsealed,
        uptime_secs: state.start_time.elapsed().as_secs(),
    })
}

async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let seal = state.seal.read().await;
    let status = seal.status();

    Json(StatusResponse {
        version: state.version,
        initialized: status != SealStatus::Uninitialized,
        sealed: status != SealStatus::Unsealed,
    })
}

async fn init_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitRequest>,
) -> Result<Json<InitResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut seal = state.seal.write().await;

    if seal.status() != SealStatus::Uninitialized {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Vault is already initialized".into(),
            }),
        ));
    }

    let config = ShamirConfig {
        shares: req.secret_shares,
        threshold: req.secret_threshold,
    };

    let result = seal.initialize(config).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    tracing::info!(
        "Vault initialized with {} shares, threshold {}",
        req.secret_shares,
        req.secret_threshold
    );

    Ok(Json(InitResponse {
        root_token: result.root_token,
        keys: result.shares.iter().map(|s| s.to_hex()).collect(),
        keys_base64: result
            .shares
            .iter()
            .map(|s| base64_encode(&s.data))
            .collect(),
    }))
}

async fn unseal_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, (StatusCode, Json<ErrorResponse>)> {
    let share = Share::from_hex(&req.key).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("Invalid key format: {}", e),
            }),
        )
    })?;

    let progress = {
        let mut seal = state.seal.write().await;

        if seal.status() == SealStatus::Uninitialized {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Vault is not initialized".into(),
                }),
            ));
        }

        if seal.status() == SealStatus::Unsealed {
            return Ok(Json(UnsealResponse {
                sealed: false,
                threshold: 0,
                progress: 0,
            }));
        }

        seal.unseal(&share).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?
    };

    // If unsealed, initialize secrets engine
    if !progress.sealed {
        state.ensure_secrets_engine().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: e }),
            )
        })?;
        tracing::info!("Vault unsealed successfully");
    } else {
        tracing::info!(
            "Unseal progress: {}/{}",
            progress.progress,
            progress.threshold
        );
    }

    Ok(Json(UnsealResponse {
        sealed: progress.sealed,
        threshold: progress.threshold,
        progress: progress.progress,
    }))
}

async fn seal_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SealResponse>, (StatusCode, Json<ErrorResponse>)> {
    {
        let mut seal = state.seal.write().await;

        if seal.status() != SealStatus::Unsealed {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Vault is not unsealed".into(),
                }),
            ));
        }

        seal.seal();
    }

    // Clear secrets engine
    state.clear_secrets_engine().await;
    tracing::info!("Vault sealed");

    Ok(Json(SealResponse { sealed: true }))
}

// ============================================================================
// Handlers - Secrets
// ============================================================================

async fn secrets_get_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<Json<SecretResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, path = %path, "secrets.get");

    let secrets = state.secrets.read().await;
    let engine = secrets.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Vault is sealed".into(),
            }),
        )
    })?;

    let secret = engine.get(&path).await.map_err(|e| {
        let status = match &e {
            egide_secrets::SecretsError::NotFound(_) => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(SecretResponse {
        data: secret.data,
        metadata: SecretMetadataResponse {
            version: secret.version,
            created_at: secret.created_at,
            deleted: false,
        },
    }))
}

async fn secrets_put_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    Json(req): Json<SecretPutRequest>,
) -> Result<Json<SecretWriteResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, path = %path, "secrets.put");

    let secrets = state.secrets.read().await;
    let engine = secrets.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Vault is sealed".into(),
            }),
        )
    })?;

    let options = egide_secrets::PutOptions {
        cas: req.cas,
        ..Default::default()
    };

    let version = engine.put(&path, req.data, options).await.map_err(|e| {
        let status = match &e {
            egide_secrets::SecretsError::VersionMismatch { .. } => StatusCode::CONFLICT,
            egide_secrets::SecretsError::InvalidPath(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(SecretWriteResponse { version }))
}

async fn secrets_delete_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, path = %path, "secrets.delete");

    let secrets = state.secrets.read().await;
    let engine = secrets.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Vault is sealed".into(),
            }),
        )
    })?;

    engine.delete(&path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn secrets_list_root_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
) -> Result<Json<SecretListResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, "secrets.list");

    let secrets = state.secrets.read().await;
    let engine = secrets.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Vault is sealed".into(),
            }),
        )
    })?;

    let items = engine.list("").await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(Json(SecretListResponse {
        keys: items.into_iter().map(|m| m.path).collect(),
    }))
}

// ============================================================================
// Utilities
// ============================================================================

fn base64_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(data)
}

/// Creates the auth service based on CLI configuration.
fn create_auth_service(cli: &Cli, seal_manager: &SealManager) -> anyhow::Result<AuthService> {
    let mut backends: Vec<Box<dyn AuthBackend>> = Vec::new();

    match cli.auth_backend {
        AuthBackendType::NubsterIdentity => {
            let jwt_secret = cli.identity_jwt_secret.clone().ok_or_else(|| {
                anyhow::anyhow!("--identity-jwt-secret is required for nubster-identity backend")
            })?;

            let config = NubsterIdentityConfig {
                jwt_secret,
                issuer: cli.identity_issuer.clone(),
                audience: cli.identity_audience.clone(),
            };

            tracing::info!(
                issuer = %config.issuer,
                audience = %config.audience,
                "Auth backend: Nubster.Identity"
            );

            backends.push(Box::new(NubsterIdentityBackend::new(config)));
        },
        AuthBackendType::RootToken => {
            tracing::info!("Auth backend: Root Token");

            // Pass the storage directly - RootTokenBackend reads async in validate()
            let storage = Arc::new(seal_manager.storage().clone());
            backends.push(Box::new(RootTokenBackend::new(storage)));
        },
    }

    Ok(AuthService::new(backends))
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,egide=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!("Starting Egide server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Data directory: {:?}", cli.data_dir);
    tracing::info!("Bind address: {}", cli.bind);

    if cli.dev {
        tracing::warn!("===========================================");
        tracing::warn!("  DEVELOPMENT MODE - DO NOT USE IN PROD!  ");
        tracing::warn!("===========================================");
    }

    // Ensure data directory exists
    tokio::fs::create_dir_all(&cli.data_dir).await?;

    // Initialize seal manager
    let mut seal_manager = SealManager::new(&cli.data_dir).await?;

    // In dev mode, enable auto-unseal
    if cli.dev {
        seal_manager.enable_dev_mode().await?;
        tracing::info!("Dev mode: auto-unseal enabled");
    }

    // Create auth service
    let auth_service = create_auth_service(&cli, &seal_manager)?;

    let state = Arc::new(AppState {
        auth: auth_service,
        seal: RwLock::new(seal_manager),
        secrets: RwLock::new(None),
        data_dir: cli.data_dir.clone(),
        start_time: Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
    });

    // If already unsealed (dev mode), initialize secrets engine
    {
        let seal = state.seal.read().await;
        if seal.status() == SealStatus::Unsealed {
            drop(seal);
            state
                .ensure_secrets_engine()
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
    }

    let app = Router::new()
        // Root
        .route("/", get(root_handler))
        // System endpoints
        .route("/v1/sys/health", get(health_handler))
        .route("/v1/sys/status", get(status_handler))
        .route("/v1/sys/init", post(init_handler))
        .route("/v1/sys/unseal", post(unseal_handler))
        .route("/v1/sys/seal", post(seal_handler))
        // Secrets endpoints
        .route("/v1/secrets", get(secrets_list_root_handler))
        .route(
            "/v1/secrets/{*path}",
            get(secrets_get_handler)
                .put(secrets_put_handler)
                .delete(secrets_delete_handler),
        )
        // Middleware
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = cli.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Egide server listening on http://{}", addr);

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
