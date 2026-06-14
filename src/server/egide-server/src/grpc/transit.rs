//! gRPC implementation of the Transit service (`TransitService`).
//!
//! Auth parity with REST handlers in `transit.rs`:
//!
//! | RPC          | Auth           | Notes                              |
//! |-------------|---------------|-------------------------------------|
//! | `CreateKey` | bearer + root  | service layer enforces root          |
//! | `DeleteKey` | bearer + root  | service layer enforces root          |
//! | `RotateKey` | bearer + root  | service layer enforces root          |
//! | `ListKeys`  | bearer (open)  | any authenticated caller             |
//! | `GetKey`    | bearer (open)  | any authenticated caller             |
//! | `Encrypt`   | bearer (open)  | plaintext is raw bytes on the wire   |
//! | `Decrypt`   | bearer (open)  | plaintext returned as raw bytes      |
//! | `Datakey`   | bearer (open)  | plaintext key returned as raw bytes  |
//! | `Rewrap`    | bearer (open)  | any authenticated caller             |

use std::sync::Arc;

use egide_api::ServiceContext;
use tonic::{Request, Response, Status};

use egide_api::proto::{
    transit_service_server::TransitService, CreateKeyRequest, CreateKeyResponse, DatakeyRequest,
    DatakeyResponse, DecryptRequest, DecryptResponse, DeleteKeyRequest, DeleteKeyResponse,
    EncryptRequest, EncryptResponse, GetKeyRequest, GetKeyResponse, ListKeysRequest,
    ListKeysResponse, RewrapRequest, RewrapResponse, RotateKeyRequest, RotateKeyResponse,
};

use crate::grpc::auth::authenticate;
use crate::grpc::status_map::to_status;

/// gRPC handler struct for the Transit domain.
///
/// Holds a shared reference to the application service context.
#[derive(Clone)]
pub struct TransitGrpc {
    /// Shared service context.
    pub state: Arc<ServiceContext>,
}

#[tonic::async_trait]
impl TransitService for TransitGrpc {
    /// Creates a transit key. Bearer + root required.
    async fn create_key(
        &self,
        request: Request<CreateKeyRequest>,
    ) -> Result<Response<CreateKeyResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let key_type = if req.key_type.is_empty() {
            "aes256-gcm"
        } else {
            &req.key_type
        };
        self.state
            .create_key(&ctx, &req.name, key_type, req.deletion_allowed)
            .await
            .map_err(to_status)?;
        Ok(Response::new(CreateKeyResponse {}))
    }

    /// Deletes a transit key. Bearer + root required.
    async fn delete_key(
        &self,
        request: Request<DeleteKeyRequest>,
    ) -> Result<Response<DeleteKeyResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        self.state
            .delete_key(&ctx, &req.name)
            .await
            .map_err(to_status)?;
        Ok(Response::new(DeleteKeyResponse {}))
    }

    /// Rotates a transit key to a new version. Bearer + root required.
    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let ctx = authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let version = self
            .state
            .rotate_key(&ctx, &req.name)
            .await
            .map_err(to_status)?;
        Ok(Response::new(RotateKeyResponse { version }))
    }

    /// Lists all transit key names. Bearer required (any authenticated caller).
    async fn list_keys(
        &self,
        request: Request<ListKeysRequest>,
    ) -> Result<Response<ListKeysResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let names = self.state.list_keys().await.map_err(to_status)?;
        Ok(Response::new(ListKeysResponse { names }))
    }

    /// Returns metadata for a transit key. Bearer required (any authenticated caller).
    async fn get_key(
        &self,
        request: Request<GetKeyRequest>,
    ) -> Result<Response<GetKeyResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let key = self.state.get_key(&req.name).await.map_err(to_status)?;
        Ok(Response::new(GetKeyResponse {
            name: key.name,
            key_type: key.key_type.to_string(),
            latest_version: key.latest_version,
            min_encryption_version: key.min_encryption_version,
            min_decryption_version: key.min_decryption_version,
            supports_encryption: key.supports_encryption,
            supports_decryption: key.supports_decryption,
            supports_derivation: key.supports_derivation,
            exportable: key.exportable,
            deletion_allowed: key.deletion_allowed,
            created_at: key.created_at,
            updated_at: key.updated_at,
        }))
    }

    /// Encrypts plaintext bytes with a transit key.
    ///
    /// The plaintext is transmitted as raw bytes on the gRPC wire (no base64).
    /// Bearer required (any authenticated caller).
    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let ciphertext = self
            .state
            .encrypt(&req.name, &req.plaintext)
            .await
            .map_err(to_status)?;
        Ok(Response::new(EncryptResponse { ciphertext }))
    }

    /// Decrypts a transit ciphertext and returns the raw plaintext bytes.
    ///
    /// The plaintext is transmitted as raw bytes on the gRPC wire (no base64).
    /// Bearer required (any authenticated caller).
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let plaintext = self
            .state
            .decrypt(&req.name, &req.ciphertext)
            .await
            .map_err(to_status)?;
        Ok(Response::new(DecryptResponse { plaintext }))
    }

    /// Generates a data encryption key wrapped under a transit key.
    ///
    /// Both the plaintext key and the wrapped ciphertext are returned.
    /// The plaintext is raw bytes; no base64 encoding.
    /// Bearer required (any authenticated caller).
    async fn datakey(
        &self,
        request: Request<DatakeyRequest>,
    ) -> Result<Response<DatakeyResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let dk = self.state.datakey(&req.name).await.map_err(to_status)?;
        Ok(Response::new(DatakeyResponse {
            plaintext: dk.plaintext,
            ciphertext: dk.ciphertext,
        }))
    }

    /// Rewraps a ciphertext with the latest transit key version.
    /// Bearer required (any authenticated caller).
    async fn rewrap(
        &self,
        request: Request<RewrapRequest>,
    ) -> Result<Response<RewrapResponse>, Status> {
        authenticate(&request, &self.state).await?;
        let req = request.into_inner();
        let ciphertext = self
            .state
            .rewrap(&req.name, &req.ciphertext)
            .await
            .map_err(to_status)?;
        Ok(Response::new(RewrapResponse { ciphertext }))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    use egide_api::proto::transit_service_server::TransitService;
    use tonic::Code;

    use crate::grpc::tests_support::unsealed_context_with_token;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    async fn fresh_svc() -> (tempfile::TempDir, TransitGrpc, String) {
        let (tmp, ctx, token) = unsealed_context_with_token().await;
        let svc = TransitGrpc { state: ctx };
        (tmp, svc, token)
    }

    fn authed<T>(inner: T, token: &str) -> Request<T> {
        let mut req = Request::new(inner);
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    }

    // ------------------------------------------------------------------
    // Task-required test: decrypt missing key -> NotFound
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn decrypt_missing_key_returns_not_found() {
        let (_tmp, svc, token) = fresh_svc().await;
        let err = svc
            .decrypt(authed(
                DecryptRequest {
                    name: "ghost".into(),
                    ciphertext: "egide:v1:AAAA".into(),
                },
                &token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
    }

    // ------------------------------------------------------------------
    // Task-required test: create_key with non-root bearer -> PermissionDenied
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn create_key_with_non_root_bearer_returns_permission_denied() {
        use crate::grpc::tests_support::unsealed_context_with_service_token;
        let (_tmp, ctx, svc_token) = unsealed_context_with_service_token().await;
        let svc = TransitGrpc { state: ctx };

        let err = svc
            .create_key(authed(
                CreateKeyRequest {
                    name: "my-key".into(),
                    key_type: "aes256-gcm".into(),
                    deletion_allowed: false,
                },
                &svc_token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    // ------------------------------------------------------------------
    // Task-required test: sealed context -> Unavailable
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn encrypt_while_sealed_returns_unavailable() {
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        // Create a key before sealing.
        ctx.create_key(
            &egide_auth::AuthContext::root(),
            "seal-test",
            "aes256-gcm",
            false,
        )
        .await
        .unwrap();
        // Seal the vault.
        ctx.seal(&egide_auth::AuthContext::root()).await.unwrap();

        let svc = TransitGrpc { state: ctx };
        let err = svc
            .encrypt(authed(
                EncryptRequest {
                    name: "seal-test".into(),
                    plaintext: b"hello".to_vec(),
                },
                &root_token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
    }

    // ------------------------------------------------------------------
    // Task-required test: happy-path encrypt->decrypt round trip
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn encrypt_decrypt_round_trip_returns_original_bytes() {
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        ctx.create_key(
            &egide_auth::AuthContext::root(),
            "rt-key",
            "aes256-gcm",
            false,
        )
        .await
        .unwrap();

        let svc = TransitGrpc { state: ctx };
        let plaintext = b"the quick brown fox";

        let ct_res = svc
            .encrypt(authed(
                EncryptRequest {
                    name: "rt-key".into(),
                    plaintext: plaintext.to_vec(),
                },
                &root_token,
            ))
            .await
            .unwrap();
        let ciphertext = ct_res.into_inner().ciphertext;

        let pt_res = svc
            .decrypt(authed(
                DecryptRequest {
                    name: "rt-key".into(),
                    ciphertext,
                },
                &root_token,
            ))
            .await
            .unwrap();
        assert_eq!(pt_res.into_inner().plaintext, plaintext);
    }

    // ------------------------------------------------------------------
    // No bearer -> Unauthenticated
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn encrypt_without_token_returns_unauthenticated() {
        let (_tmp, svc, _tok) = fresh_svc().await;
        let err = svc
            .encrypt(Request::new(EncryptRequest {
                name: "k".into(),
                plaintext: b"x".to_vec(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }

    // ------------------------------------------------------------------
    // Additional: list_keys, datakey, rewrap, get_key
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn list_keys_returns_created_key() {
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        ctx.create_key(
            &egide_auth::AuthContext::root(),
            "listed-key",
            "aes256-gcm",
            false,
        )
        .await
        .unwrap();
        let svc = TransitGrpc { state: ctx };
        let res = svc
            .list_keys(authed(ListKeysRequest {}, &root_token))
            .await
            .unwrap();
        assert!(res.into_inner().names.contains(&"listed-key".to_string()));
    }

    #[tokio::test]
    async fn get_key_returns_metadata() {
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        ctx.create_key(
            &egide_auth::AuthContext::root(),
            "meta-key",
            "aes256-gcm",
            false,
        )
        .await
        .unwrap();
        let svc = TransitGrpc { state: ctx };
        let res = svc
            .get_key(authed(
                GetKeyRequest {
                    name: "meta-key".into(),
                },
                &root_token,
            ))
            .await
            .unwrap();
        let body = res.into_inner();
        assert_eq!(body.name, "meta-key");
        assert_eq!(body.key_type, "aes256-gcm");
        assert_eq!(body.latest_version, 1);
    }

    #[tokio::test]
    async fn datakey_returns_plaintext_and_ciphertext() {
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        ctx.create_key(
            &egide_auth::AuthContext::root(),
            "dek-wrap",
            "aes256-gcm",
            false,
        )
        .await
        .unwrap();
        let svc = TransitGrpc { state: ctx };
        let res = svc
            .datakey(authed(
                DatakeyRequest {
                    name: "dek-wrap".into(),
                },
                &root_token,
            ))
            .await
            .unwrap();
        let body = res.into_inner();
        assert_eq!(body.plaintext.len(), 32);
        assert!(body.ciphertext.starts_with("egide:v1:"));
    }

    #[tokio::test]
    async fn rewrap_upgrades_ciphertext_version() {
        let (_tmp, ctx, root_token) = unsealed_context_with_token().await;
        ctx.create_key(
            &egide_auth::AuthContext::root(),
            "rw-key",
            "aes256-gcm",
            false,
        )
        .await
        .unwrap();
        let svc = TransitGrpc {
            state: Arc::clone(&ctx),
        };

        // Encrypt under v1.
        let ct_res = svc
            .encrypt(authed(
                EncryptRequest {
                    name: "rw-key".into(),
                    plaintext: b"payload".to_vec(),
                },
                &root_token,
            ))
            .await
            .unwrap();
        let ct_v1 = ct_res.into_inner().ciphertext;
        assert!(ct_v1.starts_with("egide:v1:"));

        // Rotate key via the shared state (Arc still live after clone).
        ctx.rotate_key(&egide_auth::AuthContext::root(), "rw-key")
            .await
            .unwrap();

        // Rewrap.
        let rw_res = svc
            .rewrap(authed(
                RewrapRequest {
                    name: "rw-key".into(),
                    ciphertext: ct_v1,
                },
                &root_token,
            ))
            .await
            .unwrap();
        assert!(rw_res.into_inner().ciphertext.starts_with("egide:v2:"));
    }
}
