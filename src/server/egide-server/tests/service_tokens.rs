//! Integration tests for the service token REST endpoints.
use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use egide_auth::{RootTokenBackend, ServiceTokenBackend, ServiceTokenStore};
use egide_seal::{SealManager, ShamirConfig};
use egide_server::{build_router, AppState, AuthService};
use egide_storage::StorageBackend;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tower::ServiceExt;

/// Builds an initialized + unsealed Egide router and returns a usable root token.
async fn test_app() -> (tempfile::TempDir, axum::Router, String) {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut seal_manager = SealManager::new(tmp.path()).await.expect("seal manager");
    let init = seal_manager
        .initialize(ShamirConfig {
            shares: 5,
            threshold: 3,
        })
        .await
        .expect("initialize");
    let root_token = init.root_token.clone();
    for share in init.shares.iter().take(3) {
        seal_manager.unseal(share).await.expect("unseal");
    }

    let storage: Arc<dyn StorageBackend> = Arc::new(seal_manager.storage());
    let service_store = ServiceTokenStore::new(storage);
    let auth = AuthService::new(vec![
        Box::new(RootTokenBackend::new(Arc::new(seal_manager.storage()))),
        Box::new(ServiceTokenBackend::new(service_store.clone())),
    ]);

    let state = Arc::new(AppState {
        auth,
        seal: RwLock::new(seal_manager),
        secrets: RwLock::new(None),
        transit: RwLock::new(None),
        data_dir: tmp.path().to_path_buf(),
        start_time: Instant::now(),
        version: "0.1.0",
        service_tokens: service_store,
    });
    state.ensure_secrets_engine().await.expect("secrets engine");
    state.ensure_transit_engine().await.expect("transit engine");

    (tmp, build_router(state), root_token)
}

fn request(method: &str, uri: &str, token: Option<&str>, body: &str) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn read_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(res.into_body(), usize::MAX).await.expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn create_service_token(app: &axum::Router, root: &str, name: &str) -> (String, String) {
    let res = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/auth/service-tokens",
            Some(root),
            &format!(r#"{{"service_name":"{name}"}}"#),
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = read_json(res).await;
    (
        body["token_id"].as_str().expect("token_id").to_string(),
        body["token"].as_str().expect("token").to_string(),
    )
}

#[tokio::test]
async fn create_requires_authentication() {
    let (_tmp, app, _root) = test_app().await;
    let res = app
        .oneshot(request(
            "POST",
            "/v1/auth/service-tokens",
            None,
            r#"{"service_name":"identity"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type"),
        "application/problem+json"
    );
}

#[tokio::test]
async fn root_creates_token_that_can_read_and_write_secrets() {
    let (_tmp, app, root) = test_app().await;
    let (_id, token) = create_service_token(&app, &root, "identity").await;
    assert!(token.starts_with("egst_"));

    let res = app
        .clone()
        .oneshot(request(
            "PUT",
            "/v1/secrets/app/db",
            Some(&token),
            r#"{"data":{"password":"s3cret"}}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .oneshot(request("GET", "/v1/secrets/app/db", Some(&token), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn service_token_cannot_manage_tokens() {
    let (_tmp, app, root) = test_app().await;
    let (_id, token) = create_service_token(&app, &root, "identity").await;
    let res = app
        .oneshot(request(
            "POST",
            "/v1/auth/service-tokens",
            Some(&token),
            r#"{"service_name":"evil"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_returns_metadata_without_secret() {
    let (_tmp, app, root) = test_app().await;
    create_service_token(&app, &root, "identity").await;
    let res = app
        .oneshot(request("GET", "/v1/auth/service-tokens", Some(&root), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let body = read_json(res).await.to_string();
    assert!(body.contains("identity"));
    assert!(!body.contains("egst_"));
    assert!(!body.contains("secret_hash"));
}

#[tokio::test]
async fn revoked_token_is_rejected() {
    let (_tmp, app, root) = test_app().await;
    let (id, token) = create_service_token(&app, &root, "identity").await;

    let res = app
        .clone()
        .oneshot(request(
            "DELETE",
            &format!("/v1/auth/service-tokens/{id}"),
            Some(&root),
            "",
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res = app
        .oneshot(request("GET", "/v1/secrets/app/db", Some(&token), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn seal_rejects_service_token() {
    let (_tmp, app, root) = test_app().await;
    let (_id, token) = create_service_token(&app, &root, "identity").await;
    let res = app
        .oneshot(request("POST", "/v1/sys/seal", Some(&token), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
