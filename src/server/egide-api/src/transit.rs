//! Transit domain service methods.
//!
//! Provides encryption-as-a-service: applications encrypt and decrypt data
//! without ever seeing the underlying key material.
//!
//! All operations are sealed-gated: [`ServiceError::Sealed`] is returned while
//! the vault is sealed. Key management operations (`create_key`, `delete_key`,
//! `rotate_key`) are root-only and return [`ServiceError::Forbidden`] for
//! non-root callers.

use egide_auth::AuthContext;
use egide_transit::{DataKey, KeyConfig, KeyType, TransitError, TransitKey};

use crate::{ServiceContext, ServiceError};

// ============================================================================
// Error mapping
// ============================================================================

/// Maps a [`TransitError`] to the appropriate [`ServiceError`].
///
/// The mapping faithfully transposes the REST handler's status-code decisions:
///
/// | `TransitError`                                              | `ServiceError`            |
/// |-------------------------------------------------------------|---------------------------|
/// | `KeyNotFound` / `VersionNotFound`                           | `NotFound`                |
/// | `KeyExists`                                                  | `Conflict("key already exists")` |
/// | `KeyAlgorithmNotImplemented`                                | `Conflict("key declares an algorithm this build does not implement")` |
/// | `InvalidCiphertext` / `InvalidKeyName` / `InvalidKeyType` /  | `BadRequest`              |
/// | `UnsupportedKeyType` / `VersionBelowMinEncryption` /         |                           |
/// | `VersionBelowMinDecryption` / `CiphertextAlgorithmMismatch`  |                           |
/// | `DecryptionFailed`                                          | `DecryptionFailed`        |
/// | `OperationNotAllowed` / `NotExportable` / `DeletionNotAllowed` | `Forbidden`            |
/// | `Storage` / `Crypto` / `Integrity` / `Clock`                | `Internal`                |
/// | any future variant (the enum is `#[non_exhaustive]`)        | `Internal`                |
fn map_transit_error(err: TransitError) -> ServiceError {
    match err {
        TransitError::KeyNotFound(_) | TransitError::VersionNotFound { .. } => {
            ServiceError::NotFound
        },
        TransitError::KeyExists(_) => ServiceError::Conflict("key already exists".into()),
        TransitError::KeyAlgorithmNotImplemented(_) => {
            ServiceError::Conflict("key declares an algorithm this build does not implement".into())
        },
        TransitError::InvalidCiphertext => {
            ServiceError::BadRequest("invalid ciphertext format".into())
        },
        TransitError::InvalidKeyName(msg) | TransitError::InvalidKeyType(msg) => {
            ServiceError::BadRequest(msg)
        },
        TransitError::UnsupportedKeyType(key_type) => {
            ServiceError::BadRequest(format!("unsupported key type: {key_type}"))
        },
        TransitError::VersionBelowMinEncryption { version, min } => ServiceError::BadRequest(
            format!("key version {version} is below min_encryption_version {min}"),
        ),
        TransitError::VersionBelowMinDecryption { version, min } => ServiceError::BadRequest(
            format!("key version {version} is below min_decryption_version {min}"),
        ),
        TransitError::CiphertextAlgorithmMismatch { expected, found } => ServiceError::BadRequest(
            format!("ciphertext algorithm {found} does not match engine algorithm {expected}"),
        ),
        TransitError::DecryptionFailed => ServiceError::DecryptionFailed,
        TransitError::OperationNotAllowed(msg)
        | TransitError::NotExportable(msg)
        | TransitError::DeletionNotAllowed(msg) => ServiceError::Forbidden(msg),
        TransitError::Storage(msg) | TransitError::Crypto(msg) | TransitError::Integrity(msg) => {
            ServiceError::Internal(msg)
        },
        TransitError::Clock => ServiceError::Internal("transit clock error".into()),
        // TransitError is #[non_exhaustive]: a future patch release may add a
        // variant without a major version bump. Fail closed to Internal
        // rather than fail to compile.
        _ => ServiceError::Internal("unrecognized transit error".into()),
    }
}

// ============================================================================
// Root authorization guard
// ============================================================================

/// Returns `Err(ServiceError::Forbidden)` for non-root callers.
fn require_root(ctx: &AuthContext) -> Result<(), ServiceError> {
    if ctx.is_root() {
        Ok(())
    } else {
        Err(ServiceError::Forbidden(
            "transit key management requires root privileges".into(),
        ))
    }
}

// ============================================================================
// Service methods
// ============================================================================

impl ServiceContext {
    /// Creates a new transit key with the given name and type.
    ///
    /// Authorization: root-only. Returns [`ServiceError::Forbidden`] for non-root callers.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::Conflict`] with detail `"key already exists"` if
    /// a key with the same name already exists.
    /// Returns [`ServiceError::BadRequest`] if `key_type` is not a recognized key type.
    ///
    /// If `key_type` is empty or blank, it defaults to `"aes256-gcm"`. This
    /// normalization lives here so that REST and gRPC handlers cannot drift.
    pub async fn create_key(
        &self,
        ctx: &AuthContext,
        name: &str,
        key_type: &str,
        deletion_allowed: bool,
    ) -> Result<(), ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        require_root(ctx)?;

        let effective_type = if key_type.trim().is_empty() {
            "aes256-gcm"
        } else {
            key_type
        };
        let parsed_type = effective_type
            .parse::<KeyType>()
            .map_err(map_transit_error)?;

        let mut config = KeyConfig::new();
        config.key_type = parsed_type;
        config.deletion_allowed = deletion_allowed;

        engine
            .create_key(name, config)
            .await
            .map(|_| ())
            .map_err(map_transit_error)
    }

    /// Deletes a transit key.
    ///
    /// Authorization: root-only. Returns [`ServiceError::Forbidden`] for non-root callers,
    /// or if the key does not have `deletion_allowed` set to `true`.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the key does not exist.
    pub async fn delete_key(&self, ctx: &AuthContext, name: &str) -> Result<(), ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        require_root(ctx)?;
        engine.delete_key(name).await.map_err(map_transit_error)
    }

    /// Rotates a transit key to a new version, returning the new version number.
    ///
    /// Authorization: root-only. Returns [`ServiceError::Forbidden`] for non-root callers.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the key does not exist.
    pub async fn rotate_key(&self, ctx: &AuthContext, name: &str) -> Result<u32, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        require_root(ctx)?;
        engine.rotate_key(name).await.map_err(map_transit_error)
    }

    /// Lists the names of all transit keys.
    ///
    /// Authorization: open to any authenticated bearer.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    pub async fn list_keys(&self) -> Result<Vec<String>, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine.list_keys().await.map_err(map_transit_error)
    }

    /// Returns metadata for a transit key by name.
    ///
    /// Authorization: open to any authenticated bearer.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the key does not exist.
    pub async fn get_key(&self, name: &str) -> Result<TransitKey, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine.get_key(name).await.map_err(map_transit_error)
    }

    /// Encrypts plaintext bytes with the latest version of a transit key.
    ///
    /// Returns the ciphertext string in the `egide:v{version}:{base64}` format.
    /// Base64 encoding of the plaintext is the caller's responsibility at the
    /// transport layer; this method works with raw bytes.
    ///
    /// Authorization: open to any authenticated bearer.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the key does not exist.
    pub async fn encrypt(&self, name: &str, plaintext: &[u8]) -> Result<String, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine
            .encrypt(name, plaintext)
            .await
            .map_err(map_transit_error)
    }

    /// Decrypts a transit ciphertext and returns the raw plaintext bytes.
    ///
    /// The `ciphertext` argument must be in the `egide:v{version}:{base64}` format.
    /// Base64 decoding of the result is the caller's responsibility at the
    /// transport layer; this method returns raw bytes.
    ///
    /// Decryption failures (bad authentication tag, tampered data) are reported
    /// as [`ServiceError::DecryptionFailed`] rather than a more descriptive error
    /// to prevent oracle attacks.
    ///
    /// Authorization: open to any authenticated bearer.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the key does not exist.
    pub async fn decrypt(&self, name: &str, ciphertext: &str) -> Result<Vec<u8>, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine
            .decrypt(name, ciphertext)
            .await
            .map_err(map_transit_error)
    }

    /// Rewraps a ciphertext with the latest key version without exposing plaintext.
    ///
    /// If the ciphertext is already encrypted under the latest version, it is
    /// returned unchanged.
    ///
    /// Authorization: open to any authenticated bearer.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the key does not exist.
    pub async fn rewrap(&self, name: &str, ciphertext: &str) -> Result<String, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine
            .rewrap(name, ciphertext)
            .await
            .map_err(map_transit_error)
    }

    /// Generates a data encryption key (DEK) wrapped under a transit key.
    ///
    /// Returns both the plaintext key (for immediate use by the caller) and a
    /// wrapped ciphertext for storage. The plaintext key should be used and
    /// then discarded from memory.
    ///
    /// Authorization: open to any authenticated bearer.
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the wrapping key does not exist.
    pub async fn datakey(&self, name: &str) -> Result<DataKey, ServiceError> {
        let guard = self.transit.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine
            .generate_datakey(name)
            .await
            .map_err(map_transit_error)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use egide_auth::AuthMethod;

    fn svc() -> AuthContext {
        AuthContext {
            account_id: "svc".into(),
            email: None,
            display_name: None,
            auth_method: AuthMethod::ServiceToken,
            expires_at: None,
        }
    }

    // ---- Root guard tests ------------------------------------------------

    #[tokio::test]
    async fn create_key_requires_root() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c
            .create_key(&svc(), "k1", "aes256-gcm", false)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::ServiceError::Forbidden(_)));
    }

    #[tokio::test]
    async fn delete_key_requires_root() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        // First create a key as root so the key actually exists.
        c.create_key(&AuthContext::root(), "to-delete", "aes256-gcm", true)
            .await
            .unwrap();
        let err = c.delete_key(&svc(), "to-delete").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::Forbidden(_)));
    }

    #[tokio::test]
    async fn rotate_key_requires_root() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "rotatable", "aes256-gcm", false)
            .await
            .unwrap();
        let err = c.rotate_key(&svc(), "rotatable").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::Forbidden(_)));
    }

    // ---- NotFound tests --------------------------------------------------

    #[tokio::test]
    async fn decrypt_missing_key_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c.decrypt("ghost", "egide:v1:AAAA").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn get_key_missing_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c.get_key("does-not-exist").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn encrypt_missing_key_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c.encrypt("ghost", b"hello").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn datakey_missing_key_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c.datakey("ghost").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn delete_missing_key_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c
            .delete_key(&AuthContext::root(), "ghost")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    // ---- Conflict test ---------------------------------------------------

    #[tokio::test]
    async fn create_duplicate_key_is_conflict() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "dup", "aes256-gcm", false)
            .await
            .unwrap();
        let err = c
            .create_key(&AuthContext::root(), "dup", "aes256-gcm", false)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::ServiceError::Conflict(_)));
    }

    // ---- BadRequest tests ------------------------------------------------

    #[tokio::test]
    async fn create_key_invalid_type_is_bad_request() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c
            .create_key(&AuthContext::root(), "bad-type", "rsa-4096", false)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::ServiceError::BadRequest(_)));
    }

    #[tokio::test]
    async fn decrypt_corrupt_ciphertext_format_is_bad_request() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "fmt-key", "aes256-gcm", false)
            .await
            .unwrap();
        // Malformed ciphertext (not egide:v{n}:... format).
        let err = c.decrypt("fmt-key", "notvalid").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::BadRequest(_)));
    }

    // ---- DecryptionFailed (anti-oracle) test ----------------------------

    #[tokio::test]
    async fn decrypt_tampered_ciphertext_is_decryption_failed() {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "tamper-key", "aes256-gcm", false)
            .await
            .unwrap();
        let ct = c.encrypt("tamper-key", b"secret").await.unwrap();

        // Flip bits in the base64 payload to produce a valid-format but
        // AEAD-authentication-failing ciphertext.
        let parts: Vec<&str> = ct.splitn(3, ':').collect();
        let mut bytes = BASE64.decode(parts[2]).unwrap();
        bytes[0] ^= 0xFF;
        let tampered = format!("{}:{}:{}", parts[0], parts[1], BASE64.encode(&bytes));

        let err = c.decrypt("tamper-key", &tampered).await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::DecryptionFailed));
    }

    // ---- Forbidden: delete on protected key -----------------------------

    #[tokio::test]
    async fn delete_key_without_deletion_allowed_is_forbidden() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        // Create with deletion_allowed = false (default).
        c.create_key(&AuthContext::root(), "protected", "aes256-gcm", false)
            .await
            .unwrap();
        let err = c
            .delete_key(&AuthContext::root(), "protected")
            .await
            .unwrap_err();
        assert!(matches!(err, crate::ServiceError::Forbidden(_)));
    }

    // ---- Round-trip tests -----------------------------------------------

    #[tokio::test]
    async fn encrypt_decrypt_round_trip() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "round", "aes256-gcm", false)
            .await
            .unwrap();
        let plaintext = b"the quick brown fox";
        let ct = c.encrypt("round", plaintext).await.unwrap();
        let recovered = c.decrypt("round", &ct).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn key_algorithm_not_implemented_maps_to_conflict() {
        // A key persisted under an algorithm this build does not implement
        // is a server-side state problem, not a malformed request: it must
        // map to Conflict (409), not BadRequest (400).
        let err = map_transit_error(TransitError::KeyAlgorithmNotImplemented(
            KeyType::ChaCha20Poly1305,
        ));
        assert!(
            matches!(err, crate::ServiceError::Conflict(_)),
            "expected Conflict for a legacy key's unimplemented algorithm, got {err:?}"
        );
    }

    #[test]
    fn key_exists_and_key_algorithm_not_implemented_carry_distinct_details() {
        // The whole point of carrying a detail on Conflict is that these two
        // causes, both mapped to HTTP 409, must no longer be indistinguishable.
        let exists_err = map_transit_error(TransitError::KeyExists("dup".into()));
        let unimplemented_err = map_transit_error(TransitError::KeyAlgorithmNotImplemented(
            KeyType::ChaCha20Poly1305,
        ));
        let (
            crate::ServiceError::Conflict(exists_detail),
            crate::ServiceError::Conflict(unimplemented_detail),
        ) = (exists_err, unimplemented_err)
        else {
            panic!("expected both errors to map to ServiceError::Conflict");
        };
        assert_ne!(
            exists_detail, unimplemented_detail,
            "KeyExists and KeyAlgorithmNotImplemented must carry distinct 409 details"
        );
    }

    #[tokio::test]
    async fn create_key_chacha20_is_rejected_as_unsupported() {
        // ChaCha20-Poly1305 is accepted by the wire format but not implemented
        // by the engine: creation must fail closed instead of silently
        // encrypting under AES-256-GCM.
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c
            .create_key(
                &AuthContext::root(),
                "chacha-key",
                "chacha20-poly1305",
                false,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::ServiceError::BadRequest(_)),
            "expected BadRequest for unsupported key type, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rotate_then_old_ciphertext_still_decrypts() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "rot", "aes256-gcm", false)
            .await
            .unwrap();
        let ct_v1 = c.encrypt("rot", b"v1-secret").await.unwrap();
        assert!(ct_v1.starts_with("egide:v1:"));

        let new_version = c.rotate_key(&AuthContext::root(), "rot").await.unwrap();
        assert_eq!(new_version, 2);

        let ct_v2 = c.encrypt("rot", b"v2-secret").await.unwrap();
        assert!(ct_v2.starts_with("egide:v2:"));

        assert_eq!(c.decrypt("rot", &ct_v1).await.unwrap(), b"v1-secret");
        assert_eq!(c.decrypt("rot", &ct_v2).await.unwrap(), b"v2-secret");
    }

    #[tokio::test]
    async fn rewrap_upgrades_to_latest_version() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "rw", "aes256-gcm", false)
            .await
            .unwrap();
        let ct_v1 = c.encrypt("rw", b"data").await.unwrap();
        c.rotate_key(&AuthContext::root(), "rw").await.unwrap();

        let ct_v2 = c.rewrap("rw", &ct_v1).await.unwrap();
        assert!(ct_v2.starts_with("egide:v2:"));
        assert_eq!(c.decrypt("rw", &ct_v2).await.unwrap(), b"data");
    }

    #[tokio::test]
    async fn datakey_round_trip() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "dek-wrap", "aes256-gcm", false)
            .await
            .unwrap();
        let dk = c.datakey("dek-wrap").await.unwrap();
        assert_eq!(dk.plaintext.len(), 32);
        assert!(dk.ciphertext.starts_with("egide:v1:"));

        let recovered = c.decrypt("dek-wrap", &dk.ciphertext).await.unwrap();
        assert_eq!(recovered, dk.plaintext);
    }

    #[tokio::test]
    async fn list_keys_returns_created_keys() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "alpha", "aes256-gcm", false)
            .await
            .unwrap();
        c.create_key(&AuthContext::root(), "beta", "aes256-gcm", false)
            .await
            .unwrap();
        let keys = c.list_keys().await.unwrap();
        assert!(keys.contains(&"alpha".to_string()));
        assert!(keys.contains(&"beta".to_string()));
    }

    #[tokio::test]
    async fn delete_allowed_key_succeeds() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "deletable", "aes256-gcm", true)
            .await
            .unwrap();
        c.delete_key(&AuthContext::root(), "deletable")
            .await
            .unwrap();
        let err = c.get_key("deletable").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn create_key_with_empty_type_defaults_to_aes() {
        // An empty key_type string must be silently normalized to "aes256-gcm"
        // by the service layer so that both REST and gRPC behave identically.
        let (_t, c) = crate::test_support::unsealed_context().await;
        c.create_key(&AuthContext::root(), "default-type-key", "", false)
            .await
            .expect("create_key with empty type should succeed");
        let key = c.get_key("default-type-key").await.expect("get_key");
        assert_eq!(
            key.key_type.to_string(),
            "aes256-gcm",
            "empty key_type should default to aes256-gcm"
        );
    }

    #[tokio::test]
    async fn create_key_non_empty_invalid_type_is_bad_request() {
        // A non-empty but unrecognized key_type must still return BadRequest.
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c
            .create_key(&AuthContext::root(), "bad-type2", "rsa-4096", false)
            .await
            .unwrap_err();
        assert!(
            matches!(err, crate::ServiceError::BadRequest(_)),
            "expected BadRequest for unknown type, got {err:?}"
        );
    }
}
