//! Native service tokens: opaque `egst_<id>.<secret>` credentials issued by Egide.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public prefix of an Egide service token.
pub const SERVICE_TOKEN_PREFIX: &str = "egst_";

/// Storage key prefix under which service token records are persisted.
pub const SERVICE_TOKEN_STORAGE_PREFIX: &str = "service-tokens/";

/// Persisted record for a service token. Only the secret hash is stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceTokenRecord {
    /// Public token identifier (lookup key).
    pub token_id: String,
    /// Hex-encoded SHA-256 hash of the token secret.
    pub secret_hash: String,
    /// Name of the service the token belongs to.
    pub service_name: String,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Revocation timestamp (Unix seconds), if revoked.
    pub revoked_at: Option<u64>,
}

/// Parses an opaque service token of the form `egst_<token_id>.<secret>`.
///
/// Returns `None` if the prefix is missing, the separator is absent, or either
/// part is empty.
#[must_use]
pub fn parse_token(token: &str) -> Option<(String, String)> {
    let rest = token.strip_prefix(SERVICE_TOKEN_PREFIX)?;
    let (id, secret) = rest.split_once('.')?;
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id.to_string(), secret.to_string()))
}

/// Formats a service token from its identifier and secret.
#[must_use]
pub fn format_token(token_id: &str, secret: &str) -> String {
    format!("{SERVICE_TOKEN_PREFIX}{token_id}.{secret}")
}

/// Computes the hex-encoded SHA-256 hash of a token secret.
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    hex::encode(Sha256::digest(secret.as_bytes()))
}

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use egide_storage::StorageBackend;
use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::{AuthBackend, AuthContext, AuthError, AuthMethod};

/// Stores and manages native service tokens via the raw storage backend.
#[derive(Clone)]
pub struct ServiceTokenStore {
    storage: Arc<dyn StorageBackend>,
}

impl ServiceTokenStore {
    /// Creates a new store over the given storage backend.
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }

    fn storage_key(token_id: &str) -> String {
        format!("{SERVICE_TOKEN_STORAGE_PREFIX}{token_id}")
    }

    /// Creates a new service token for `service_name`.
    pub async fn create(&self, service_name: &str) -> Result<(String, String), AuthError> {
        let mut id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let token_id = hex::encode(id_bytes);

        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret = hex::encode(secret_bytes);

        let record = ServiceTokenRecord {
            token_id: token_id.clone(),
            secret_hash: hash_secret(&secret),
            service_name: service_name.to_string(),
            created_at: now_unix(),
            revoked_at: None,
        };
        self.write(&record).await?;
        Ok((token_id.clone(), format_token(&token_id, &secret)))
    }

    /// Looks up a record by token identifier.
    pub async fn lookup(&self, token_id: &str) -> Result<Option<ServiceTokenRecord>, AuthError> {
        match self
            .storage
            .get(&Self::storage_key(token_id))
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?
        {
            Some(bytes) => {
                let record = serde_json::from_slice(&bytes)
                    .map_err(|e| AuthError::Storage(e.to_string()))?;
                Ok(Some(record))
            },
            None => Ok(None),
        }
    }

    /// Lists all service token records.
    pub async fn list(&self) -> Result<Vec<ServiceTokenRecord>, AuthError> {
        let keys = self
            .storage
            .list(SERVICE_TOKEN_STORAGE_PREFIX)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))?;
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(bytes) = self
                .storage
                .get(&key)
                .await
                .map_err(|e| AuthError::Storage(e.to_string()))?
            {
                records.push(
                    serde_json::from_slice(&bytes)
                        .map_err(|e| AuthError::Storage(e.to_string()))?,
                );
            }
        }
        Ok(records)
    }

    /// Revokes a token. Returns `true` if the token existed.
    pub async fn revoke(&self, token_id: &str) -> Result<bool, AuthError> {
        match self.lookup(token_id).await? {
            Some(mut record) => {
                if record.revoked_at.is_none() {
                    record.revoked_at = Some(now_unix());
                    self.write(&record).await?;
                }
                Ok(true)
            },
            None => Ok(false),
        }
    }

    async fn write(&self, record: &ServiceTokenRecord) -> Result<(), AuthError> {
        let value = serde_json::to_vec(record).map_err(|e| AuthError::Storage(e.to_string()))?;
        self.storage
            .put(&Self::storage_key(&record.token_id), &value)
            .await
            .map_err(|e| AuthError::Storage(e.to_string()))
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Authentication backend validating native service tokens.
pub struct ServiceTokenBackend {
    store: ServiceTokenStore,
}

impl ServiceTokenBackend {
    /// Creates a new backend over the given store.
    #[must_use]
    pub fn new(store: ServiceTokenStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl AuthBackend for ServiceTokenBackend {
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        let (token_id, secret) = parse_token(token).ok_or(AuthError::InvalidCredentials)?;
        let record = self
            .store
            .lookup(&token_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        if record.revoked_at.is_some() {
            return Err(AuthError::InvalidCredentials);
        }

        let candidate = hash_secret(&secret);
        if !bool::from(candidate.as_bytes().ct_eq(record.secret_hash.as_bytes())) {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(AuthContext {
            account_id: record.service_name,
            email: None,
            display_name: None,
            auth_method: AuthMethod::ServiceToken,
            expires_at: None,
        })
    }

    fn name(&self) -> &'static str {
        "service-token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use egide_storage::{StorageBackend, StorageError};
    use tokio::sync::Mutex;

    struct MemoryStorage {
        data: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MemoryStorage {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for MemoryStorage {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.data.lock().await.get(key).cloned())
        }

        async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
            self.data
                .lock()
                .await
                .insert(key.to_string(), value.to_vec());
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.data.lock().await.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
            Ok(self
                .data
                .lock()
                .await
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    fn store() -> ServiceTokenStore {
        ServiceTokenStore::new(Arc::new(MemoryStorage::new()))
    }

    #[tokio::test]
    async fn create_then_lookup_roundtrip() {
        let s = store();
        let (token_id, raw_token) = s.create("my-service").await.expect("create failed");
        assert!(raw_token.starts_with("egst_"));
        let record = s
            .lookup(&token_id)
            .await
            .expect("lookup failed")
            .expect("record must exist");
        assert_eq!(record.service_name, "my-service");
        assert_eq!(record.token_id, token_id);
        assert!(record.revoked_at.is_none());
    }

    #[tokio::test]
    async fn lookup_unknown_returns_none() {
        let s = store();
        let result = s.lookup("nonexistent").await.expect("lookup failed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_returns_created_records() {
        let s = store();
        s.create("svc-a").await.expect("create svc-a failed");
        s.create("svc-b").await.expect("create svc-b failed");
        let records = s.list().await.expect("list failed");
        assert_eq!(records.len(), 2);
        let names: Vec<&str> = records.iter().map(|r| r.service_name.as_str()).collect();
        assert!(names.contains(&"svc-a"));
        assert!(names.contains(&"svc-b"));
    }

    #[tokio::test]
    async fn revoke_marks_record_and_reports_existence() {
        let s = store();
        let (token_id, _) = s.create("svc").await.expect("create failed");

        let existed = s.revoke(&token_id).await.expect("revoke failed");
        assert!(existed);

        let record = s
            .lookup(&token_id)
            .await
            .expect("lookup failed")
            .expect("record must exist after revoke");
        assert!(record.revoked_at.is_some());

        let not_found = s.revoke("unknown-id").await.expect("revoke failed");
        assert!(!not_found);
    }

    #[test]
    fn parses_a_well_formed_token() {
        let parsed = parse_token("egst_abc123.deadbeef");
        assert_eq!(parsed, Some(("abc123".to_string(), "deadbeef".to_string())));
    }

    #[test]
    fn rejects_token_without_prefix() {
        assert_eq!(parse_token("abc123.deadbeef"), None);
    }

    #[test]
    fn rejects_token_without_separator() {
        assert_eq!(parse_token("egst_abc123deadbeef"), None);
    }

    #[test]
    fn rejects_token_with_empty_parts() {
        assert_eq!(parse_token("egst_.deadbeef"), None);
        assert_eq!(parse_token("egst_abc123."), None);
    }

    #[test]
    fn formats_a_token() {
        assert_eq!(format_token("abc", "sec"), "egst_abc.sec");
    }

    #[test]
    fn hash_is_stable_and_hex() {
        let h = hash_secret("hello");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_secret("hello"));
        assert_ne!(h, hash_secret("world"));
    }

    #[tokio::test]
    async fn validates_a_live_token() {
        let s = store();
        let backend = ServiceTokenBackend::new(s.clone());
        let (_, raw_token) = s.create("my-svc").await.expect("create failed");
        let ctx = backend.validate(&raw_token).await.expect("validate failed");
        assert_eq!(ctx.account_id, "my-svc");
        assert_eq!(ctx.auth_method, crate::AuthMethod::ServiceToken);
        assert!(!ctx.is_root());
    }

    #[tokio::test]
    async fn rejects_unknown_and_revoked_identically() {
        let s = store();
        let backend = ServiceTokenBackend::new(s.clone());

        // Unknown token
        let err_unknown = backend
            .validate("egst_0000.deadbeef")
            .await
            .expect_err("should reject unknown token");
        assert!(
            err_unknown
                .to_string()
                .to_lowercase()
                .contains("invalid credentials"),
            "expected 'invalid credentials', got: {err_unknown}"
        );

        // Revoked token
        let (token_id, raw_token) = s.create("svc").await.expect("create failed");
        s.revoke(&token_id).await.expect("revoke failed");
        let err_revoked = backend
            .validate(&raw_token)
            .await
            .expect_err("should reject revoked token");
        assert!(
            err_revoked
                .to_string()
                .to_lowercase()
                .contains("invalid credentials"),
            "expected 'invalid credentials', got: {err_revoked}"
        );

        // Both map to the same variant
        assert_eq!(
            std::mem::discriminant(&err_unknown),
            std::mem::discriminant(&err_revoked)
        );
    }

    #[tokio::test]
    async fn rejects_wrong_secret() {
        let s = store();
        let backend = ServiceTokenBackend::new(s.clone());
        let (token_id, _) = s.create("svc").await.expect("create failed");
        let forged = format!("egst_{token_id}.wrongsecret");
        let err = backend
            .validate(&forged)
            .await
            .expect_err("should reject wrong secret");
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("invalid credentials"));
    }

    #[tokio::test]
    async fn rejects_malformed_token() {
        let s = store();
        let backend = ServiceTokenBackend::new(s);
        let err = backend
            .validate("not-a-token")
            .await
            .expect_err("should reject malformed token");
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("invalid credentials"));
    }
}
