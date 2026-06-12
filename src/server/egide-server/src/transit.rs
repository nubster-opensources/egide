//! HTTP handlers for the Transit engine (`/v1/transit/*`).
//!
//! Key management (create, rotate, delete) is root-only; reads and data
//! operations are open to any authenticated bearer. The engine is unseal-gated,
//! so every route returns `503` while the server is sealed.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use egide_auth::AuthContext;
use egide_transit::{KeyConfig, KeyType, TransitError};

use crate::{AppState, Authenticated, Problem};

// ============================================================================
// Guards and error mapping
// ============================================================================

/// Problem returned when a transit route is hit while the server is sealed.
fn sealed() -> Problem {
    Problem::new(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed")
}

/// Rejects non-root callers from key management routes.
fn require_root(ctx: &AuthContext) -> Result<(), Problem> {
    if ctx.is_root() {
        Ok(())
    } else {
        Err(Problem::new(
            StatusCode::FORBIDDEN,
            "transit key management requires root privileges",
        ))
    }
}

/// Maps a `TransitError` to an RFC 9457 problem response.
fn transit_problem(err: TransitError) -> Problem {
    let status = match &err {
        TransitError::KeyNotFound(_) | TransitError::VersionNotFound { .. } => {
            StatusCode::NOT_FOUND
        },
        TransitError::KeyExists(_) => StatusCode::CONFLICT,
        TransitError::InvalidCiphertext
        | TransitError::InvalidKeyName(_)
        | TransitError::InvalidKeyType(_)
        | TransitError::VersionBelowMinEncryption { .. }
        | TransitError::VersionBelowMinDecryption { .. }
        | TransitError::DecryptionFailed => StatusCode::BAD_REQUEST,
        TransitError::OperationNotAllowed(_)
        | TransitError::NotExportable(_)
        | TransitError::DeletionNotAllowed(_) => StatusCode::FORBIDDEN,
        TransitError::Storage(_) | TransitError::Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Problem::new(status, err.to_string())
}

// ============================================================================
// Request / response bodies
// ============================================================================

/// Body for `POST /v1/transit/keys`.
#[derive(Deserialize)]
pub struct CreateKeyRequest {
    /// Key name.
    pub name: String,
    /// Optional key type (`aes256-gcm` default, or `chacha20-poly1305`).
    #[serde(rename = "type")]
    pub key_type: Option<String>,
    /// Whether the key may later be deleted (default false).
    #[serde(default)]
    pub deletion_allowed: bool,
}

/// Response for a created key.
#[derive(Serialize)]
pub struct KeyCreatedResponse {
    name: String,
    #[serde(rename = "type")]
    key_type: String,
    latest_version: u32,
}

/// Response for `GET /v1/transit/keys`.
#[derive(Serialize)]
pub struct ListKeysResponse {
    keys: Vec<String>,
}

/// Response for `GET /v1/transit/keys/{name}`.
#[derive(Serialize)]
pub struct KeyInfoResponse {
    name: String,
    #[serde(rename = "type")]
    key_type: String,
    latest_version: u32,
    min_encryption_version: u32,
    min_decryption_version: u32,
    supports_encryption: bool,
    supports_decryption: bool,
    deletion_allowed: bool,
}

/// Response for `POST /v1/transit/keys/{name}/rotate`.
#[derive(Serialize)]
pub struct RotateResponse {
    version: u32,
}

/// Body carrying an opaque transit ciphertext (`egide:v{n}:...`).
#[derive(Deserialize)]
pub struct CiphertextRequest {
    /// Ciphertext produced by a previous encrypt/datakey/rewrap call.
    pub ciphertext: String,
}

/// Body carrying base64-encoded plaintext.
#[derive(Deserialize)]
pub struct PlaintextRequest {
    /// Base64-encoded plaintext.
    pub plaintext: String,
}

/// Response carrying an opaque ciphertext.
#[derive(Serialize)]
pub struct CiphertextResponse {
    ciphertext: String,
}

/// Response carrying base64-encoded plaintext.
#[derive(Serialize)]
pub struct PlaintextResponse {
    plaintext: String,
}

/// Response for `POST /v1/transit/datakey/{name}`.
#[derive(Serialize)]
pub struct DataKeyResponse {
    plaintext: String,
    ciphertext: String,
}

// ============================================================================
// Handlers - key management
// ============================================================================

/// Handles `POST /v1/transit/keys` (root-only).
pub async fn create_key_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<KeyCreatedResponse>), Problem> {
    require_root(&ctx)?;

    let key_type = match req.key_type.as_deref() {
        None => KeyType::default(),
        Some(raw) => raw.parse::<KeyType>().map_err(transit_problem)?,
    };

    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;

    let mut config = KeyConfig::new();
    config.key_type = key_type;
    config.deletion_allowed = req.deletion_allowed;

    let key = engine
        .create_key(&req.name, config)
        .await
        .map_err(transit_problem)?;

    Ok((
        StatusCode::CREATED,
        Json(KeyCreatedResponse {
            name: key.name,
            key_type: key.key_type.to_string(),
            latest_version: key.latest_version,
        }),
    ))
}

/// Handles `GET /v1/transit/keys`.
pub async fn list_keys_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ListKeysResponse>, Problem> {
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let keys = engine.list_keys().await.map_err(transit_problem)?;
    Ok(Json(ListKeysResponse { keys }))
}

/// Handles `GET /v1/transit/keys/{name}`.
pub async fn get_key_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<KeyInfoResponse>, Problem> {
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let key = engine.get_key(&name).await.map_err(transit_problem)?;
    Ok(Json(KeyInfoResponse {
        name: key.name,
        key_type: key.key_type.to_string(),
        latest_version: key.latest_version,
        min_encryption_version: key.min_encryption_version,
        min_decryption_version: key.min_decryption_version,
        supports_encryption: key.supports_encryption,
        supports_decryption: key.supports_decryption,
        deletion_allowed: key.deletion_allowed,
    }))
}

/// Handles `DELETE /v1/transit/keys/{name}` (root-only).
pub async fn delete_key_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, Problem> {
    require_root(&ctx)?;
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    engine.delete_key(&name).await.map_err(transit_problem)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Handles `POST /v1/transit/keys/{name}/rotate` (root-only).
pub async fn rotate_key_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<RotateResponse>, Problem> {
    require_root(&ctx)?;
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let version = engine.rotate_key(&name).await.map_err(transit_problem)?;
    Ok(Json(RotateResponse { version }))
}

// ============================================================================
// Handlers - data operations
// ============================================================================

/// Handles `POST /v1/transit/encrypt/{name}`.
pub async fn encrypt_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<PlaintextRequest>,
) -> Result<Json<CiphertextResponse>, Problem> {
    let plaintext = BASE64
        .decode(req.plaintext.as_bytes())
        .map_err(|_| Problem::new(StatusCode::BAD_REQUEST, "plaintext must be valid base64"))?;
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let ciphertext = engine
        .encrypt(&name, &plaintext)
        .await
        .map_err(transit_problem)?;
    Ok(Json(CiphertextResponse { ciphertext }))
}

/// Handles `POST /v1/transit/decrypt/{name}`.
pub async fn decrypt_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<CiphertextRequest>,
) -> Result<Json<PlaintextResponse>, Problem> {
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let plaintext = engine
        .decrypt(&name, &req.ciphertext)
        .await
        .map_err(transit_problem)?;
    Ok(Json(PlaintextResponse {
        plaintext: BASE64.encode(&plaintext),
    }))
}

/// Handles `POST /v1/transit/datakey/{name}`.
pub async fn datakey_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<DataKeyResponse>, Problem> {
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let datakey = engine
        .generate_datakey(&name)
        .await
        .map_err(transit_problem)?;
    Ok(Json(DataKeyResponse {
        plaintext: BASE64.encode(&datakey.plaintext),
        ciphertext: datakey.ciphertext,
    }))
}

/// Handles `POST /v1/transit/rewrap/{name}`.
pub async fn rewrap_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<CiphertextRequest>,
) -> Result<Json<CiphertextResponse>, Problem> {
    let transit = state.transit.read().await;
    let engine = transit.as_ref().ok_or_else(sealed)?;
    let ciphertext = engine
        .rewrap(&name, &req.ciphertext)
        .await
        .map_err(transit_problem)?;
    Ok(Json(CiphertextResponse { ciphertext }))
}
