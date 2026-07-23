//! Secrets domain service methods.
//!
//! All operations require the vault to be unsealed. They are open to any authenticated bearer
//! (no root privilege required).

use std::collections::HashMap;

use egide_secrets::{PutOptions, SecretMetadata, SecretsError};

use crate::{ServiceContext, ServiceError};

/// A decrypted secret view returned by the service layer.
#[derive(Debug, Clone)]
pub struct SecretView {
    /// Decrypted key-value data.
    pub data: HashMap<String, String>,
    /// Version number of this secret.
    pub version: u32,
    /// Creation timestamp of this version (Unix seconds).
    ///
    /// Preserved from the storage layer so REST adapters can reproduce the
    /// `metadata.created_at` field with byte-identical semantics.
    pub created_at: u64,
}

impl ServiceContext {
    /// Retrieves the current version of a secret at the given path.
    ///
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the path does not exist or has been deleted.
    pub async fn secret_get(&self, path: &str) -> Result<SecretView, ServiceError> {
        let guard = self.secrets.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        match engine.get(path).await {
            Ok(s) => Ok(SecretView {
                data: s.data,
                version: s.version,
                created_at: s.created_at,
            }),
            Err(e) if is_not_found(&e) => Err(ServiceError::NotFound),
            Err(e) => Err(ServiceError::Internal(e.to_string())),
        }
    }

    /// Stores or updates a secret at the given path.
    ///
    /// Returns the new version number. When `cas` is `Some(n)`, the write only
    /// succeeds if the current version equals `n`; a mismatch yields
    /// [`ServiceError::Conflict`] (HTTP 409) with a detail explaining the
    /// version mismatch. Passing `None` performs an unconditional write.
    ///
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::BadRequest`] if the path is invalid.
    pub async fn secret_put(
        &self,
        path: &str,
        data: HashMap<String, String>,
        cas: Option<u32>,
    ) -> Result<u32, ServiceError> {
        let guard = self.secrets.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        let options = PutOptions {
            cas,
            ..Default::default()
        };
        engine.put(path, data, options).await.map_err(map_put_error)
    }

    /// Soft-deletes the secret at the given path.
    ///
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    /// Returns [`ServiceError::NotFound`] if the path does not exist or is already deleted.
    pub async fn secret_delete(&self, path: &str) -> Result<(), ServiceError> {
        let guard = self.secrets.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        match engine.delete(path).await {
            Ok(()) => Ok(()),
            Err(e) if is_not_found(&e) => Err(ServiceError::NotFound),
            Err(e) => Err(ServiceError::Internal(e.to_string())),
        }
    }

    /// Lists secrets whose path starts with the given prefix.
    ///
    /// Returns [`ServiceError::Sealed`] if the vault is sealed.
    pub async fn secret_list(&self, prefix: &str) -> Result<Vec<SecretMetadata>, ServiceError> {
        let guard = self.secrets.read().await;
        let engine = guard.as_ref().ok_or(ServiceError::Sealed)?;
        engine
            .list(prefix)
            .await
            .map_err(|e| ServiceError::Internal(e.to_string()))
    }
}

/// Maps a [`SecretsError`] from a `put` call to the appropriate [`ServiceError`].
///
/// | `SecretsError`         | `ServiceError`        | HTTP |
/// |------------------------|-----------------------|------|
/// | `VersionMismatch`      | `Conflict`            | 409  |
/// | `InvalidPath`          | `BadRequest`          | 400  |
/// | everything else        | `Internal`            | 500  |
fn map_put_error(e: SecretsError) -> ServiceError {
    match e {
        SecretsError::VersionMismatch { .. } => ServiceError::Conflict(
            "version mismatch: the current version differs from the one provided".into(),
        ),
        SecretsError::InvalidPath(msg) => ServiceError::BadRequest(msg),
        other => ServiceError::Internal(other.to_string()),
    }
}

/// Returns `true` when the error represents a missing or deleted secret.
fn is_not_found(e: &SecretsError) -> bool {
    matches!(e, SecretsError::NotFound(_) | SecretsError::Deleted(_))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c.secret_get("nope/x").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn put_then_get_returns_same_data_and_version_one() {
        let (_t, c) = crate::test_support::unsealed_context().await;

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "s3cr3t".to_string());

        let version = c.secret_put("myapp/db", data.clone(), None).await.unwrap();
        assert_eq!(version, 1);

        let view = c.secret_get("myapp/db").await.unwrap();
        assert_eq!(view.version, 1);
        assert_eq!(view.data.get("username").unwrap(), "admin");
        assert_eq!(view.data.get("password").unwrap(), "s3cr3t");
    }

    #[tokio::test]
    async fn delete_missing_is_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;
        let err = c.secret_delete("ghost/key").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn delete_removes_secret_and_get_returns_not_found() {
        let (_t, c) = crate::test_support::unsealed_context().await;

        let mut data = HashMap::new();
        data.insert("key".to_string(), "value".to_string());
        c.secret_put("app/temp", data, None).await.unwrap();

        c.secret_delete("app/temp").await.unwrap();

        let err = c.secret_get("app/temp").await.unwrap_err();
        assert!(matches!(err, crate::ServiceError::NotFound));
    }

    #[tokio::test]
    async fn list_returns_entries_under_prefix() {
        let (_t, c) = crate::test_support::unsealed_context().await;

        let mut d = HashMap::new();
        d.insert("k".to_string(), "v".to_string());

        c.secret_put("svc/alpha", d.clone(), None).await.unwrap();
        c.secret_put("svc/beta", d.clone(), None).await.unwrap();
        c.secret_put("other/x", d, None).await.unwrap();

        let entries = c.secret_list("svc/").await.unwrap();
        assert_eq!(entries.len(), 2);

        let empty = c.secret_list("missing/").await.unwrap();
        assert!(empty.is_empty());
    }

    // ---- CAS (check-and-set) ------------------------------------------------

    #[tokio::test]
    async fn put_with_stale_cas_is_conflict() {
        let (_t, c) = crate::test_support::unsealed_context().await;

        let mut data = HashMap::new();
        data.insert("k".to_string(), "v1".to_string());

        // First write: unconditional, returns version 1.
        c.secret_put("cas/stale", data.clone(), None).await.unwrap();

        let mut data2 = HashMap::new();
        data2.insert("k".to_string(), "v2".to_string());

        // cas: Some(0) is stale (current version is 1), must yield Conflict.
        let err = c.secret_put("cas/stale", data2, Some(0)).await.unwrap_err();
        assert!(
            matches!(err, crate::ServiceError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );
    }

    #[tokio::test]
    async fn put_with_correct_cas_succeeds() {
        let (_t, c) = crate::test_support::unsealed_context().await;

        let mut data = HashMap::new();
        data.insert("k".to_string(), "v1".to_string());

        // First write: unconditional, returns version 1.
        let v1 = c
            .secret_put("cas/correct", data.clone(), None)
            .await
            .unwrap();
        assert_eq!(v1, 1);

        let mut data2 = HashMap::new();
        data2.insert("k".to_string(), "v2".to_string());

        // cas: Some(1) matches the current version, must succeed and return 2.
        let v2 = c.secret_put("cas/correct", data2, Some(1)).await.unwrap();
        assert_eq!(v2, 2);
    }

    #[tokio::test]
    async fn put_without_cas_overwrites_unconditionally() {
        let (_t, c) = crate::test_support::unsealed_context().await;

        let mut data = HashMap::new();
        data.insert("k".to_string(), "v1".to_string());

        c.secret_put("cas/unconditional", data.clone(), None)
            .await
            .unwrap();

        let mut data2 = HashMap::new();
        data2.insert("k".to_string(), "v2".to_string());

        // No CAS guard: unconditional overwrite must succeed.
        let v2 = c
            .secret_put("cas/unconditional", data2, None)
            .await
            .unwrap();
        assert_eq!(v2, 2);

        let view = c.secret_get("cas/unconditional").await.unwrap();
        assert_eq!(view.data.get("k").unwrap(), "v2");
    }
}
