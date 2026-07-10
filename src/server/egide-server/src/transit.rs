//! HTTP handlers for the Transit engine (`/v1/transit/*`).
//!
//! Key management (create, rotate, delete) is root-only; reads and data
//! operations are open to any authenticated bearer. The engine is unseal-gated,
//! so every route returns `503` while the server is sealed. Authorization and
//! seal-gating are enforced by the service layer; handlers are thin adapters.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use crate::{AppState, Authenticated, Problem};

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
///
/// The default key type normalization (absent/empty -> `"aes256-gcm"`) is
/// applied by the service layer so that REST and gRPC behave identically.
pub async fn create_key_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<KeyCreatedResponse>), Problem> {
    let key_type = req.key_type.as_deref().unwrap_or("");
    state
        .create_key(&ctx, &req.name, key_type, req.deletion_allowed)
        .await
        .map_err(Problem::from)?;
    // Retrieve key metadata to build the response (preserves the original body shape).
    let key = state.get_key(&req.name).await.map_err(Problem::from)?;
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
    let keys = state.list_keys().await.map_err(Problem::from)?;
    Ok(Json(ListKeysResponse { keys }))
}

/// Handles `GET /v1/transit/keys/{name}`.
pub async fn get_key_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<KeyInfoResponse>, Problem> {
    let key = state.get_key(&name).await.map_err(Problem::from)?;
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
    state.delete_key(&ctx, &name).await.map_err(Problem::from)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Handles `POST /v1/transit/keys/{name}/rotate` (root-only).
pub async fn rotate_key_handler(
    Authenticated(ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<RotateResponse>, Problem> {
    let version = state.rotate_key(&ctx, &name).await.map_err(Problem::from)?;
    Ok(Json(RotateResponse { version }))
}

// ============================================================================
// Handlers - data operations
// ============================================================================

/// Handles `POST /v1/transit/encrypt/{name}`.
///
/// The request carries base64-encoded plaintext; the handler decodes it before
/// calling the service (which works with raw bytes). Base64 is a REST concern.
pub async fn encrypt_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<PlaintextRequest>,
) -> Result<Json<CiphertextResponse>, Problem> {
    let plaintext = BASE64
        .decode(req.plaintext.as_bytes())
        .map_err(|_| Problem::new(StatusCode::BAD_REQUEST, "plaintext must be valid base64"))?;
    let ciphertext = state
        .encrypt(&name, &plaintext)
        .await
        .map_err(Problem::from)?;
    Ok(Json(CiphertextResponse { ciphertext }))
}

/// Handles `POST /v1/transit/decrypt/{name}`.
///
/// The service returns raw bytes; the handler base64-encodes them for the JSON
/// response. Base64 is a REST concern.
pub async fn decrypt_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<CiphertextRequest>,
) -> Result<Json<PlaintextResponse>, Problem> {
    let plaintext = state
        .decrypt(&name, &req.ciphertext)
        .await
        .map_err(Problem::from)?;
    Ok(Json(PlaintextResponse {
        plaintext: BASE64.encode(&plaintext),
    }))
}

/// Handles `POST /v1/transit/datakey/{name}`.
///
/// The plaintext key bytes are base64-encoded in the response. Base64 is a REST concern.
pub async fn datakey_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<DataKeyResponse>, Problem> {
    let datakey = state.datakey(&name).await.map_err(Problem::from)?;
    let (plaintext, ciphertext) = datakey.into_parts();
    Ok(Json(DataKeyResponse {
        plaintext: BASE64.encode(plaintext),
        ciphertext,
    }))
}

/// Handles `POST /v1/transit/rewrap/{name}`.
pub async fn rewrap_handler(
    Authenticated(_ctx): Authenticated,
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(req): Json<CiphertextRequest>,
) -> Result<Json<CiphertextResponse>, Problem> {
    let ciphertext = state
        .rewrap(&name, &req.ciphertext)
        .await
        .map_err(Problem::from)?;
    Ok(Json(CiphertextResponse { ciphertext }))
}
