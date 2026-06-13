//! Egide Server library - router, state, handlers.

pub mod problem;
pub use problem::Problem;

pub mod transit;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub use egide_api::ServiceContext as AppState;
pub use egide_auth::AuthService;
use egide_auth::{
    AuthContext, AuthError, RootTokenBackend, ServiceTokenBackend, ServiceTokenStore,
};
use egide_seal::SealManager;

/// Authenticated request extractor.
///
/// Validates the `Authorization: Bearer <token>` header (RFC 6750) and returns
/// the authentication context.
pub struct Authenticated(pub AuthContext);

impl FromRequestParts<Arc<AppState>> for Authenticated {
    type Rejection = Problem;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Problem::new(StatusCode::UNAUTHORIZED, "missing bearer token"))?;

        let ctx = state.auth.validate(token).await.map_err(|e| {
            let detail = match e {
                AuthError::TokenExpired => "token expired",
                _ => "invalid credentials",
            };
            Problem::new(StatusCode::UNAUTHORIZED, detail)
        })?;

        Ok(Authenticated(ctx))
    }
}

// ============================================================================
// CLI Arguments
// ============================================================================

/// Command-line arguments for the Egide server.
#[derive(Parser)]
#[command(name = "egide-server")]
#[command(about = "Nubster Egide - Secrets management server")]
#[command(version)]
pub struct Cli {
    /// Data directory for persistent storage.
    #[arg(long, default_value = "./data", env = "EGIDE_DATA_DIR")]
    pub data_dir: PathBuf,

    /// Enable development mode (auto-unseal, NOT FOR PRODUCTION).
    #[arg(long, env = "EGIDE_DEV_MODE")]
    pub dev: bool,

    /// Server bind address.
    #[arg(long, default_value = "0.0.0.0:8200", env = "EGIDE_BIND_ADDRESS")]
    pub bind: String,
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Health check response body.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    initialized: bool,
    sealed: bool,
    uptime_secs: u64,
}

/// Status response body.
#[derive(Serialize)]
pub struct StatusResponse {
    version: &'static str,
    initialized: bool,
    sealed: bool,
}

/// Init request body.
#[derive(Deserialize)]
pub struct InitRequest {
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

/// Init response body.
#[derive(Serialize)]
pub struct InitResponse {
    root_token: String,
    keys: Vec<String>,
    keys_base64: Vec<String>,
}

/// Unseal request body.
#[derive(Deserialize)]
pub struct UnsealRequest {
    key: String,
}

/// Unseal response body.
#[derive(Serialize)]
pub struct UnsealResponse {
    sealed: bool,
    threshold: u8,
    progress: u8,
}

/// Seal response body.
#[derive(Serialize)]
pub struct SealResponse {
    sealed: bool,
}

/// Error response body.
#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

// Secrets types

/// Secret write request body.
#[derive(Deserialize)]
pub struct SecretPutRequest {
    data: std::collections::HashMap<String, String>,
    /// Check-and-set version guard: only write if the current version equals this value.
    /// Omit (or pass `null`) for an unconditional write.
    #[serde(default)]
    cas: Option<u32>,
}

/// Secret read response body.
#[derive(Serialize)]
pub struct SecretResponse {
    data: std::collections::HashMap<String, String>,
    metadata: SecretMetadataResponse,
}

/// Secret metadata within a read response.
#[derive(Serialize)]
pub struct SecretMetadataResponse {
    version: u32,
    created_at: u64,
    deleted: bool,
}

/// Secret write response body.
#[derive(Serialize)]
pub struct SecretWriteResponse {
    version: u32,
}

/// Secret list response body.
#[derive(Serialize)]
pub struct SecretListResponse {
    keys: Vec<String>,
}

// Service token types

#[derive(serde::Deserialize)]
struct CreateServiceTokenRequest {
    service_name: String,
}

#[derive(serde::Serialize)]
struct CreateServiceTokenResponse {
    token_id: String,
    token: String,
}

#[derive(serde::Serialize)]
struct ServiceTokenMetadata {
    token_id: String,
    service_name: String,
    created_at: u64,
    revoked_at: Option<u64>,
}

// ============================================================================
// Handlers - System
// ============================================================================

/// Handles GET `/`.
pub async fn root_handler() -> &'static str {
    "Egide - Secrets Management Server"
}

/// Handles GET `/v1/sys/health`.
pub async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let sv = state.status().await;
    Json(HealthResponse {
        status: "ok",
        version: sv.version,
        initialized: sv.initialized,
        sealed: sv.sealed,
        uptime_secs: state.start_time.elapsed().as_secs(),
    })
}

/// Handles GET `/v1/sys/status`.
pub async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let sv = state.status().await;
    Json(StatusResponse {
        version: sv.version,
        initialized: sv.initialized,
        sealed: sv.sealed,
    })
}

/// Handles POST `/v1/sys/init`.
///
/// Init is a bootstrap operation: no bearer token is required. The service layer
/// enforces that init can only succeed when the vault is not yet initialized.
pub async fn init_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InitRequest>,
) -> Result<Json<InitResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Bootstrap context: init is open to any caller (the shares are the credential).
    let view = state
        .init(
            &AuthContext::root(),
            req.secret_shares,
            req.secret_threshold,
        )
        .await
        .map_err(|e| {
            use egide_api::ServiceError as E;
            let status = match &e {
                E::BadRequest(_) => StatusCode::BAD_REQUEST,
                E::Forbidden(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
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
        root_token: view.root_token,
        keys: view.shares_hex,
        keys_base64: view.shares_base64,
    }))
}

/// Handles POST `/v1/sys/unseal`.
pub async fn unseal_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnsealRequest>,
) -> Result<Json<UnsealResponse>, (StatusCode, Json<ErrorResponse>)> {
    let view = state.unseal(&req.key).await.map_err(|e| {
        use egide_api::ServiceError as E;
        let status = match &e {
            E::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    if !view.sealed {
        tracing::info!("Vault unsealed successfully");
    } else {
        tracing::info!("Unseal progress: {}/{}", view.progress, view.threshold);
    }

    Ok(Json(UnsealResponse {
        sealed: view.sealed,
        threshold: view.threshold,
        progress: view.progress,
    }))
}

/// Handles POST `/v1/sys/seal`.
pub async fn seal_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
) -> Result<Json<SealResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.seal(&ctx).await.map_err(|e| {
        use egide_api::ServiceError as E;
        let status = match &e {
            E::Forbidden(_) => StatusCode::FORBIDDEN,
            E::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    tracing::info!("Vault sealed");
    Ok(Json(SealResponse { sealed: true }))
}

// ============================================================================
// Handlers - Secrets
// ============================================================================

/// Handles GET `/v1/secrets/{*path}`.
pub async fn secrets_get_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<Json<SecretResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, path = %path, "secrets.get");

    let view = state.secret_get(&path).await.map_err(|e| {
        use egide_api::ServiceError as E;
        let status = match &e {
            E::NotFound => StatusCode::NOT_FOUND,
            E::Sealed => StatusCode::SERVICE_UNAVAILABLE,
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
        data: view.data,
        metadata: SecretMetadataResponse {
            version: view.version,
            created_at: view.created_at,
            deleted: false,
        },
    }))
}

/// Handles PUT `/v1/secrets/{*path}`.
pub async fn secrets_put_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    Json(req): Json<SecretPutRequest>,
) -> Result<Json<SecretWriteResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, path = %path, "secrets.put");

    let version = state
        .secret_put(&path, req.data, req.cas)
        .await
        .map_err(|e| {
            use egide_api::ServiceError as E;
            let status = match &e {
                E::Conflict => StatusCode::CONFLICT,
                E::BadRequest(_) => StatusCode::BAD_REQUEST,
                E::Sealed => StatusCode::SERVICE_UNAVAILABLE,
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

/// Handles DELETE `/v1/secrets/{*path}`.
pub async fn secrets_delete_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, path = %path, "secrets.delete");

    state.secret_delete(&path).await.map_err(|e| {
        use egide_api::ServiceError as E;
        let status = match &e {
            E::NotFound => StatusCode::NOT_FOUND,
            E::Sealed => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Handles GET `/v1/secrets`.
pub async fn secrets_list_root_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
) -> Result<Json<SecretListResponse>, (StatusCode, Json<ErrorResponse>)> {
    tracing::debug!(account = %ctx.account_id, "secrets.list");

    let items = state.secret_list("").await.map_err(|e| {
        use egide_api::ServiceError as E;
        let status = match &e {
            E::Sealed => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
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
// Handlers - Service Tokens
// ============================================================================

/// Handles POST `/v1/auth/service-tokens`.
async fn service_token_create_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateServiceTokenRequest>,
) -> Result<(StatusCode, Json<CreateServiceTokenResponse>), Problem> {
    let (token_id, token) = state
        .create_service_token(&ctx, &req.service_name)
        .await
        .map_err(Problem::from)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateServiceTokenResponse { token_id, token }),
    ))
}

/// Handles GET `/v1/auth/service-tokens`.
async fn service_token_list_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ServiceTokenMetadata>>, Problem> {
    let records = state
        .list_service_tokens(&ctx)
        .await
        .map_err(Problem::from)?;
    let metadata = records
        .into_iter()
        .map(|r| ServiceTokenMetadata {
            token_id: r.token_id,
            service_name: r.service_name,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        })
        .collect();
    Ok(Json(metadata))
}

/// Handles DELETE `/v1/auth/service-tokens/{token_id}`.
async fn service_token_revoke_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(token_id): axum::extract::Path<String>,
) -> Result<StatusCode, Problem> {
    state
        .revoke_service_token(&ctx, &token_id)
        .await
        .map_err(Problem::from)?;
    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Utilities
// ============================================================================

/// Creates the auth service composing root-token and service-token backends.
fn create_auth_service(
    seal_manager: &SealManager,
    service_store: ServiceTokenStore,
) -> AuthService {
    let root = RootTokenBackend::new(Arc::new(seal_manager.storage().clone()));
    let service = ServiceTokenBackend::new(service_store);
    tracing::info!("Auth backends: root-token, service-token");
    AuthService::new(vec![Box::new(root), Box::new(service)])
}

// ============================================================================
// Router and server startup
// ============================================================================

/// Builds the axum router for the given application state.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(root_handler))
        .route("/v1/sys/health", get(health_handler))
        .route("/v1/sys/status", get(status_handler))
        .route("/v1/sys/init", post(init_handler))
        .route("/v1/sys/unseal", post(unseal_handler))
        .route("/v1/sys/seal", post(seal_handler))
        .route("/v1/secrets", get(secrets_list_root_handler))
        .route(
            "/v1/secrets/{*path}",
            get(secrets_get_handler)
                .put(secrets_put_handler)
                .delete(secrets_delete_handler),
        )
        .route(
            "/v1/auth/service-tokens",
            post(service_token_create_handler).get(service_token_list_handler),
        )
        .route(
            "/v1/auth/service-tokens/{token_id}",
            delete(service_token_revoke_handler),
        )
        .route(
            "/v1/transit/keys",
            post(transit::create_key_handler).get(transit::list_keys_handler),
        )
        .route(
            "/v1/transit/keys/{name}",
            get(transit::get_key_handler).delete(transit::delete_key_handler),
        )
        .route(
            "/v1/transit/keys/{name}/rotate",
            post(transit::rotate_key_handler),
        )
        .route("/v1/transit/encrypt/{name}", post(transit::encrypt_handler))
        .route("/v1/transit/decrypt/{name}", post(transit::decrypt_handler))
        .route("/v1/transit/datakey/{name}", post(transit::datakey_handler))
        .route("/v1/transit/rewrap/{name}", post(transit::rewrap_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Runs the server: builds state from the CLI, binds and serves.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,egide=debug".into()),
        )
        .init();

    tracing::info!("Starting Egide server v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Data directory: {:?}", cli.data_dir);
    tracing::info!("Bind address: {}", cli.bind);

    if cli.dev {
        tracing::warn!("===========================================");
        tracing::warn!("  DEVELOPMENT MODE - DO NOT USE IN PROD!  ");
        tracing::warn!("===========================================");
    }

    // Ensure data directory exists.
    tokio::fs::create_dir_all(&cli.data_dir).await?;

    // Initialize seal manager.
    let mut seal_manager = SealManager::new(&cli.data_dir).await?;

    // In dev mode, enable auto-unseal.
    if cli.dev {
        seal_manager.enable_dev_mode().await?;
        tracing::info!("Dev mode: auto-unseal enabled");
    }

    // Build shared service token store.
    let service_store = ServiceTokenStore::new(
        Arc::new(seal_manager.storage().clone()) as Arc<dyn egide_storage::StorageBackend>
    );
    let auth_service = create_auth_service(&seal_manager, service_store.clone());

    let state = Arc::new(AppState {
        auth: auth_service,
        seal: RwLock::new(seal_manager),
        secrets: RwLock::new(None),
        transit: RwLock::new(None),
        data_dir: cli.data_dir.clone(),
        start_time: Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
        service_tokens: service_store,
    });

    // If already unsealed (dev mode), initialize the engines.
    {
        let sv = state.status().await;
        if !sv.sealed {
            state
                .ensure_secrets_engine()
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            state
                .ensure_transit_engine()
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
        }
    }

    let app = build_router(state.clone());

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
