//! # Egide Storage - `PostgreSQL` Backend
//!
//! `PostgreSQL` implementation of the storage backend with schema-per-tenant
//! isolation. Each tenant gets its own Postgres schema; every query qualifies
//! its tables explicitly, so tenant isolation never depends on session state.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::{debug, info};

use egide_storage::{StorageBackend, StorageError};

/// `PostgreSQL` storage backend with schema-per-tenant isolation.
///
/// Each tenant maps to a dedicated Postgres schema. All queries qualify their
/// tables as `"{tenant}".kv_store` / `"{tenant}".kv_history`. The tenant name is
/// interpolated into SQL (a schema identifier cannot be a bind parameter), so
/// the `[a-z0-9_-]+` validation in [`PostgresBackend::connect`] is the single
/// anti-injection barrier.
#[derive(Clone)]
pub struct PostgresBackend {
    pool: PgPool,
    tenant: String,
    actor: Option<String>,
}

impl PostgresBackend {
    /// Connects to Postgres and prepares the tenant schema.
    ///
    /// # Arguments
    ///
    /// * `database_url` - Postgres connection URL
    /// * `tenant` - Tenant identifier (must match `[a-z0-9_-]+`)
    ///
    /// # Errors
    ///
    /// Returns an error if the tenant name is invalid, the connection fails,
    /// or the schema migration fails.
    pub async fn connect(database_url: &str, tenant: &str) -> Result<Self, StorageError> {
        Self::validate_tenant(tenant)?;

        debug!(tenant = %tenant, "Opening Postgres connection");

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;

        let backend = Self {
            pool,
            tenant: tenant.to_string(),
            actor: None,
        };

        backend.migrate().await?;

        info!(tenant = %tenant, "Postgres backend ready");

        Ok(backend)
    }

    /// Sets the actor for audit logging.
    ///
    /// Returns a new instance with the actor set. All operations performed with
    /// this instance will be logged with this actor.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Returns the current actor, if set.
    #[must_use]
    pub fn current_actor(&self) -> Option<String> {
        self.actor.clone()
    }

    /// Validates that a tenant name is safe.
    ///
    /// Only allows: lowercase letters, digits, underscore, hyphen. This is also
    /// the anti-injection guard for the interpolated schema name.
    fn validate_tenant(tenant: &str) -> Result<(), StorageError> {
        if tenant.is_empty() {
            return Err(StorageError::InvalidInput("tenant cannot be empty".into()));
        }

        if tenant.len() > 64 {
            return Err(StorageError::InvalidInput("tenant name too long".into()));
        }

        let valid = tenant
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');

        if !valid {
            return Err(StorageError::InvalidInput(
                "tenant must match [a-z0-9_-]+".into(),
            ));
        }

        Ok(())
    }

    /// Runs schema migrations for the tenant.
    ///
    /// Creates the tenant schema and all required tables if they do not exist.
    async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{}\"", self.tenant))
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS "{}".kv_store (
                key        TEXT PRIMARY KEY,
                value      BYTEA NOT NULL,
                version    BIGINT NOT NULL DEFAULT 1,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL
            )
            "#,
            self.tenant
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS "{}".kv_history (
                id         BIGSERIAL PRIMARY KEY,
                key        TEXT NOT NULL,
                value      BYTEA,
                version    BIGINT NOT NULL,
                operation  TEXT NOT NULL,
                actor      TEXT,
                timestamp  BIGINT NOT NULL
            )
            "#,
            self.tenant
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS idx_history_key ON \"{}\".kv_history (key)",
            self.tenant
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS idx_history_timestamp ON \"{}\".kv_history (timestamp)",
            self.tenant
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        debug!("Migrations complete");

        Ok(())
    }

    /// Returns the current Unix timestamp in seconds.
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs()
            .cast_signed()
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let sql = format!(
            "SELECT value FROM \"{}\".kv_store WHERE key = $1",
            self.tenant
        );

        let row: Option<(Vec<u8>,)> = sqlx::query_as(&sql)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(row.map(|(v,)| v))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let now = Self::now();

        let select_sql = format!(
            "SELECT version FROM \"{}\".kv_store WHERE key = $1",
            self.tenant
        );
        let existing: Option<(i64,)> = sqlx::query_as(&select_sql)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        let (version, operation) = match existing {
            Some((v,)) => (v + 1, "update"),
            None => (1, "create"),
        };

        let upsert_sql = format!(
            r#"
            INSERT INTO "{}".kv_store (key, value, version, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (key) DO UPDATE SET
                value = EXCLUDED.value,
                version = EXCLUDED.version,
                updated_at = EXCLUDED.updated_at
            "#,
            self.tenant
        );
        sqlx::query(&upsert_sql)
            .bind(key)
            .bind(value)
            .bind(version)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        let history_sql = format!(
            "INSERT INTO \"{}\".kv_history (key, value, version, operation, actor, timestamp) VALUES ($1, $2, $3, $4, $5, $6)",
            self.tenant
        );
        sqlx::query(&history_sql)
            .bind(key)
            .bind(value)
            .bind(version)
            .bind(operation)
            .bind(self.actor.as_deref())
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let select_sql = format!(
            "SELECT version FROM \"{}\".kv_store WHERE key = $1",
            self.tenant
        );
        let existing: Option<(i64,)> = sqlx::query_as(&select_sql)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        if let Some((version,)) = existing {
            let now = Self::now();

            let delete_sql = format!("DELETE FROM \"{}\".kv_store WHERE key = $1", self.tenant);
            sqlx::query(&delete_sql)
                .bind(key)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

            let history_sql = format!(
                "INSERT INTO \"{}\".kv_history (key, value, version, operation, actor, timestamp) VALUES ($1, NULL, $2, 'delete', $3, $4)",
                self.tenant
            );
            sqlx::query(&history_sql)
                .bind(key)
                .bind(version + 1)
                .bind(self.actor.as_deref())
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        }

        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let pattern = format!("{prefix}%");
        let sql = format!(
            "SELECT key FROM \"{}\".kv_store WHERE key LIKE $1",
            self.tenant
        );

        let rows: Vec<(String,)> = sqlx::query_as(&sql)
            .bind(&pattern)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(rows.into_iter().map(|(k,)| k).collect())
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;
    use testcontainers_modules::testcontainers::ContainerAsync;

    // A bogus URL is fine: validation rejects invalid tenants before the pool
    // is ever opened, so these tests need no Docker.
    const ANY_URL: &str = "postgres://unused:unused@127.0.0.1:1/unused";

    /// Starts an ephemeral Postgres container and returns it with its URL.
    /// The returned container must be kept alive for the test duration.
    async fn start_postgres() -> (ContainerAsync<Postgres>, String) {
        let node = Postgres::default().start().await.unwrap();
        let port = node.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        (node, url)
    }

    /// Builds a backend on a fresh container with the `test-tenant` schema.
    async fn setup() -> (ContainerAsync<Postgres>, PostgresBackend) {
        let (node, url) = start_postgres().await;
        let backend = PostgresBackend::connect(&url, "test-tenant").await.unwrap();
        (node, backend)
    }

    #[tokio::test]
    async fn test_tenant_validation_empty() {
        let result = PostgresBackend::connect(ANY_URL, "").await;
        assert!(matches!(result, Err(StorageError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn test_tenant_validation_too_long() {
        let long = "a".repeat(65);
        let result = PostgresBackend::connect(ANY_URL, &long).await;
        assert!(matches!(result, Err(StorageError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn test_tenant_validation_invalid_chars() {
        let invalid_names = [
            "Tenant",
            "my tenant",
            "tenant/sub",
            "../escape",
            "tenant.db",
        ];

        for name in invalid_names {
            let result = PostgresBackend::connect(ANY_URL, name).await;
            assert!(
                matches!(result, Err(StorageError::InvalidInput(_))),
                "expected InvalidInput for tenant name: {name}"
            );
        }
    }

    #[tokio::test]
    async fn test_crud_roundtrip() {
        let (_node, backend) = setup().await;

        let result = backend.get("secret/key").await.unwrap();
        assert!(result.is_none());

        backend.put("secret/key", b"secret-value").await.unwrap();

        let result = backend.get("secret/key").await.unwrap();
        assert_eq!(result, Some(b"secret-value".to_vec()));

        backend.put("secret/key", b"new-value").await.unwrap();
        let result = backend.get("secret/key").await.unwrap();
        assert_eq!(result, Some(b"new-value".to_vec()));
    }

    #[tokio::test]
    async fn test_version_increments() {
        let (_node, backend) = setup().await;

        backend.put("key", b"v1").await.unwrap();
        backend.put("key", b"v2").await.unwrap();
        backend.put("key", b"v3").await.unwrap();

        let sql = "SELECT version FROM \"test-tenant\".kv_store WHERE key = $1";
        let row: (i64,) = sqlx::query_as(sql)
            .bind("key")
            .fetch_one(&backend.pool)
            .await
            .unwrap();

        assert_eq!(row.0, 3);
    }

    #[tokio::test]
    async fn test_binary_data() {
        let (_node, backend) = setup().await;

        let binary_data: Vec<u8> = (0..=255).collect();
        backend.put("binary", &binary_data).await.unwrap();

        let result = backend.get("binary").await.unwrap();
        assert_eq!(result, Some(binary_data));
    }

    #[tokio::test]
    async fn test_with_actor() {
        let (_node, backend) = setup().await;
        let backend = backend.with_actor("user:alice");

        backend.put("key", b"value").await.unwrap();

        let sql = "SELECT actor FROM \"test-tenant\".kv_history WHERE key = $1";
        let row: (String,) = sqlx::query_as(sql)
            .bind("key")
            .fetch_one(&backend.pool)
            .await
            .unwrap();

        assert_eq!(row.0, "user:alice");
    }

    #[tokio::test]
    async fn test_delete_roundtrip() {
        let (_node, backend) = setup().await;

        backend.put("secret/key", b"secret-value").await.unwrap();
        backend.delete("secret/key").await.unwrap();
        let result = backend.get("secret/key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_is_ok() {
        let (_node, backend) = setup().await;

        backend.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn test_history_records_operations() {
        let (_node, backend) = setup().await;
        let backend = backend.with_actor("system");

        backend.put("key", b"v1").await.unwrap();
        backend.put("key", b"v2").await.unwrap();
        backend.delete("key").await.unwrap();

        let sql =
            "SELECT operation, version FROM \"test-tenant\".kv_history WHERE key = $1 ORDER BY id";
        let rows: Vec<(String, i64)> = sqlx::query_as(sql)
            .bind("key")
            .fetch_all(&backend.pool)
            .await
            .unwrap();

        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0], ("create".to_string(), 1));
        assert_eq!(rows[1], ("update".to_string(), 2));
        assert_eq!(rows[2], ("delete".to_string(), 3));
    }

    #[tokio::test]
    async fn test_list_prefix() {
        let (_node, backend) = setup().await;

        backend.put("prod/app/db", b"1").await.unwrap();
        backend.put("prod/app/api", b"2").await.unwrap();
        backend.put("prod/other/key", b"3").await.unwrap();
        backend.put("dev/app/db", b"4").await.unwrap();

        let mut keys = backend.list("prod/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["prod/app/api", "prod/app/db", "prod/other/key"]);

        let mut keys = backend.list("prod/app/").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["prod/app/api", "prod/app/db"]);

        let keys = backend.list("staging/").await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn test_list_all() {
        let (_node, backend) = setup().await;

        backend.put("a", b"1").await.unwrap();
        backend.put("b", b"2").await.unwrap();

        let mut keys = backend.list("").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        // Two tenants (two schemas) on the SAME Postgres instance.
        let (_node, url) = start_postgres().await;

        let backend_a = PostgresBackend::connect(&url, "tenant-a").await.unwrap();
        let backend_b = PostgresBackend::connect(&url, "tenant-b").await.unwrap();

        backend_a.put("shared-key", b"value-a").await.unwrap();
        backend_b.put("shared-key", b"value-b").await.unwrap();

        assert_eq!(
            backend_a.get("shared-key").await.unwrap(),
            Some(b"value-a".to_vec())
        );
        assert_eq!(
            backend_b.get("shared-key").await.unwrap(),
            Some(b"value-b".to_vec())
        );
    }
}
