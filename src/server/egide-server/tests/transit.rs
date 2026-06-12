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

/// Builds an initialized, unsealed router with transit + secrets engines ready.
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
    state.ensure_transit_engine().await.expect("transit engine");

    (tmp, build_router(state), root_token)
}

/// Builds an initialized but still-sealed router (transit engine stays None).
async fn test_app_sealed() -> (tempfile::TempDir, axum::Router, String) {
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
    // Intentionally not unsealed: engines remain None.

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

/// Creates a service token via the root token and returns the bearer string.
async fn service_token(app: &axum::Router, root: &str) -> String {
    let res = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/auth/service-tokens",
            Some(root),
            r#"{"service_name":"identity"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::CREATED);
    read_json(res).await["token"]
        .as_str()
        .expect("token")
        .to_string()
}

#[tokio::test]
async fn root_creates_key() {
    let (_tmp, app, root) = test_app().await;
    let res = app
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&root),
            r#"{"name":"app-kek"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = read_json(res).await;
    assert_eq!(body["name"], "app-kek");
    assert_eq!(body["type"], "aes256-gcm");
    assert_eq!(body["latest_version"], 1);
}

#[tokio::test]
async fn create_key_requires_authentication() {
    let (_tmp, app, _root) = test_app().await;
    let res = app
        .oneshot(request("POST", "/v1/transit/keys", None, r#"{"name":"x"}"#))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn service_token_cannot_create_key() {
    let (_tmp, app, root) = test_app().await;
    let token = service_token(&app, &root).await;
    let res = app
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&token),
            r#"{"name":"x"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_key_unknown_type_is_400() {
    let (_tmp, app, root) = test_app().await;
    let res = app
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&root),
            r#"{"name":"k","type":"rot13"}"#,
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_and_get_key_allow_service_token() {
    let (_tmp, app, root) = test_app().await;
    app.clone()
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&root),
            r#"{"name":"app-kek"}"#,
        ))
        .await
        .expect("oneshot");
    let token = service_token(&app, &root).await;

    let res = app
        .clone()
        .oneshot(request("GET", "/v1/transit/keys", Some(&token), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(read_json(res).await.to_string().contains("app-kek"));

    let res = app
        .oneshot(request("GET", "/v1/transit/keys/app-kek", Some(&token), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    let body = read_json(res).await;
    assert_eq!(body["name"], "app-kek");
    assert_eq!(body["latest_version"], 1);
}

#[tokio::test]
async fn get_unknown_key_is_404() {
    let (_tmp, app, root) = test_app().await;
    let res = app
        .oneshot(request("GET", "/v1/transit/keys/nope", Some(&root), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rotate_bumps_version_and_is_root_only() {
    let (_tmp, app, root) = test_app().await;
    app.clone()
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&root),
            r#"{"name":"k"}"#,
        ))
        .await
        .expect("oneshot");

    let token = service_token(&app, &root).await;
    let res = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/transit/keys/k/rotate",
            Some(&token),
            "",
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app
        .oneshot(request(
            "POST",
            "/v1/transit/keys/k/rotate",
            Some(&root),
            "",
        ))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(read_json(res).await["version"], 2);
}

#[tokio::test]
async fn delete_allowed_key_then_missing() {
    let (_tmp, app, root) = test_app().await;
    app.clone()
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&root),
            r#"{"name":"k","deletion_allowed":true}"#,
        ))
        .await
        .expect("oneshot");

    let res = app
        .clone()
        .oneshot(request("DELETE", "/v1/transit/keys/k", Some(&root), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res = app
        .oneshot(request("GET", "/v1/transit/keys/k", Some(&root), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_protected_key_is_403() {
    let (_tmp, app, root) = test_app().await;
    app.clone()
        .oneshot(request(
            "POST",
            "/v1/transit/keys",
            Some(&root),
            r#"{"name":"k"}"#,
        ))
        .await
        .expect("oneshot");
    let res = app
        .oneshot(request("DELETE", "/v1/transit/keys/k", Some(&root), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn management_route_when_sealed_is_503() {
    let (_tmp, app, root) = test_app_sealed().await;
    let res = app
        .oneshot(request("GET", "/v1/transit/keys", Some(&root), ""))
        .await
        .expect("oneshot");
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}
