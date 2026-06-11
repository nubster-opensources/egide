//! # Egide Storage - SQLite Backend
//!
//! SQLite implementation of the storage backend with tenant isolation.
//! Each tenant gets its own database file for maximum security.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use tracing::{debug, info};

use egide_storage::{StorageBackend, StorageError};

/// SQLite storage backend with tenant isolation.
///
/// Each tenant gets its own database file at `{base_path}/{tenant}.db`.
/// This ensures complete data isolation between tenants.
#[derive(Clone)]
pub struct SqliteBackend {
    pool: SqlitePool,
    actor: Option<String>,
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl SqliteBackend {
    /// Opens or creates a SQLite database for a tenant.
    ///
    /// # Arguments
    ///
    /// * `base_path` - Directory where tenant databases are stored
    /// * `tenant` - Tenant identifier (must match `[a-z0-9_-]+`)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Tenant name is invalid
    /// - Directory cannot be created
    /// - Database connection fails
    pub async fn open(base_path: impl AsRef<Path>, tenant: &str) -> Result<Self, StorageError> {
        Self::validate_tenant(tenant)?;

        let base = base_path.as_ref();
        std::fs::create_dir_all(base).map_err(|e| {
            StorageError::ConnectionFailed(format!("failed to create directory: {e}"))
        })?;

        let db_path = base.join(format!("{tenant}.db"));
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

        debug!(tenant = %tenant, path = %db_path.display(), "Opening SQLite database");

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;

        let backend = Self {
            pool,
            actor: None,
            db_path,
        };

        backend.migrate().await?;

        info!(tenant = %tenant, "SQLite backend ready");

        Ok(backend)
    }

    /// Sets the actor for audit logging.
    ///
    /// Returns a new instance with the actor set. All operations
    /// performed with this instance will be logged with this actor.
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Validates that a tenant name is safe.
    ///
    /// Only allows: lowercase letters, digits, underscore, hyphen.
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

    /// Runs database migrations.
    async fn migrate(&self) -> Result<(), StorageError> {
        debug!("Running database migrations");

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS kv_store (
                key        TEXT PRIMARY KEY,
                value      BLOB NOT NULL,
                version    INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS kv_history (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                key        TEXT NOT NULL,
                value      BLOB,
                version    INTEGER NOT NULL,
                operation  TEXT NOT NULL,
                actor      TEXT,
                timestamp  INTEGER NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_history_key ON kv_history (key)")
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_history_timestamp ON kv_history (timestamp)")
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::ConnectionFailed(format!("migration failed: {e}")))?;

        debug!("Migrations complete");

        Ok(())
    }

    /// Returns the current Unix timestamp.
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs() as i64
    }

    /// Returns the current actor, if set.
    pub fn current_actor(&self) -> Option<String> {
        self.actor.clone()
    }

    /// Executes raw SQL statements (for migrations/schema creation).
    pub async fn execute_raw(&self, sql: &str) -> Result<(), StorageError> {
        for statement in sql.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(statement.trim())
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// Executes a SQL statement with parameters.
    pub async fn execute(&self, sql: &str, params: &[&str]) -> Result<(), StorageError> {
        let mut query = sqlx::query(sql);
        for param in params {
            query = query.bind(*param);
        }
        query
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(())
    }

    /// Queries a single row with typed results.
    pub async fn query_one<T>(&self, sql: &str, params: &[&str]) -> Result<Option<T>, StorageError>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
    {
        let mut query = sqlx::query_as::<_, T>(sql);
        for param in params {
            query = query.bind(*param);
        }
        query
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))
    }

    /// Queries multiple rows with typed results.
    pub async fn query_all<T>(&self, sql: &str, params: &[&str]) -> Result<Vec<T>, StorageError>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> + Send + Unpin,
    {
        let mut query = sqlx::query_as::<_, T>(sql);
        for param in params {
            query = query.bind(*param);
        }
        query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))
    }
}

#[async_trait]
impl StorageBackend for SqliteBackend {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let row: Option<(Vec<u8>,)> = sqlx::query_as("SELECT value FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(row.map(|(v,)| v))
    }

    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let now = Self::now();

        let existing: Option<(i64,)> = sqlx::query_as("SELECT version FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        let (version, operation) = match existing {
            Some((v,)) => (v + 1, "update"),
            None => (1, "create"),
        };

        sqlx::query(
            r#"
            INSERT INTO kv_store (key, value, version, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                version = excluded.version,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(key)
        .bind(value)
        .bind(version)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        sqlx::query(
            "INSERT INTO kv_history (key, value, version, operation, actor, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        )
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
        let existing: Option<(i64,)> = sqlx::query_as("SELECT version FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        if let Some((version,)) = existing {
            let now = Self::now();

            sqlx::query("DELETE FROM kv_store WHERE key = ?")
                .bind(key)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

            sqlx::query(
                "INSERT INTO kv_history (key, value, version, operation, actor, timestamp) VALUES (?, NULL, ?, 'delete', ?, ?)",
            )
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

        let rows: Vec<(String,)> = sqlx::query_as("SELECT key FROM kv_store WHERE key LIKE ?")
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
    use tempfile::TempDir;

    async fn setup() -> (TempDir, SqliteBackend) {
        let tmp = TempDir::new().unwrap();
        let backend = SqliteBackend::open(tmp.path(), "test-tenant")
            .await
            .unwrap();
        (tmp, backend)
    }

    #[tokio::test]
    async fn test_open_creates_db() {
        let tmp = TempDir::new().unwrap();
        let _backend = SqliteBackend::open(tmp.path(), "my-tenant").await.unwrap();

        let db_path = tmp.path().join("my-tenant.db");
        assert!(db_path.exists(), "database file should be created");
    }

    #[tokio::test]
    async fn test_tenant_validation_empty() {
        let tmp = TempDir::new().unwrap();
        let result = SqliteBackend::open(tmp.path(), "").await;
        assert!(matches!(result, Err(StorageError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn test_tenant_validation_invalid_chars() {
        let tmp = TempDir::new().unwrap();

        let invalid_names = [
            "Tenant",
            "my tenant",
            "tenant/sub",
            "../escape",
            "tenant.db",
        ];

        for name in invalid_names {
            let result = SqliteBackend::open(tmp.path(), name).await;
            assert!(
                matches!(result, Err(StorageError::InvalidInput(_))),
                "should reject tenant name: {name}"
            );
        }
    }

    #[tokio::test]
    async fn test_tenant_validation_valid() {
        let tmp = TempDir::new().unwrap();

        let valid_names = ["tenant", "my-tenant", "tenant_1", "123", "a-b_c"];

        for name in valid_names {
            let result = SqliteBackend::open(tmp.path(), name).await;
            assert!(result.is_ok(), "should accept tenant name: {name}");
        }
    }

    #[tokio::test]
    async fn test_crud_roundtrip() {
        let (_tmp, backend) = setup().await;

        // Get non-existent key
        let result = backend.get("secret/key").await.unwrap();
        assert!(result.is_none());

        // Put
        backend.put("secret/key", b"secret-value").await.unwrap();

        // Get
        let result = backend.get("secret/key").await.unwrap();
        assert_eq!(result, Some(b"secret-value".to_vec()));

        // Update
        backend.put("secret/key", b"new-value").await.unwrap();
        let result = backend.get("secret/key").await.unwrap();
        assert_eq!(result, Some(b"new-value".to_vec()));

        // Delete
        backend.delete("secret/key").await.unwrap();
        let result = backend.get("secret/key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_is_ok() {
        let (_tmp, backend) = setup().await;

        // Should not error
        backend.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn test_list_prefix() {
        let (_tmp, backend) = setup().await;

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
        let (_tmp, backend) = setup().await;

        backend.put("a", b"1").await.unwrap();
        backend.put("b", b"2").await.unwrap();

        let mut keys = backend.list("").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn test_with_actor() {
        let (_tmp, backend) = setup().await;
        let backend = backend.with_actor("user:alice");

        backend.put("key", b"value").await.unwrap();

        // Verify actor in history
        let row: (String,) = sqlx::query_as("SELECT actor FROM kv_history WHERE key = ?")
            .bind("key")
            .fetch_one(&backend.pool)
            .await
            .unwrap();

        assert_eq!(row.0, "user:alice");
    }

    #[tokio::test]
    async fn test_history_records_operations() {
        let (_tmp, backend) = setup().await;
        let backend = backend.with_actor("system");

        // Create
        backend.put("key", b"v1").await.unwrap();
        // Update
        backend.put("key", b"v2").await.unwrap();
        // Delete
        backend.delete("key").await.unwrap();

        let rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT operation, version FROM kv_history WHERE key = ? ORDER BY id")
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
    async fn test_version_increments() {
        let (_tmp, backend) = setup().await;

        backend.put("key", b"v1").await.unwrap();
        backend.put("key", b"v2").await.unwrap();
        backend.put("key", b"v3").await.unwrap();

        let row: (i64,) = sqlx::query_as("SELECT version FROM kv_store WHERE key = ?")
            .bind("key")
            .fetch_one(&backend.pool)
            .await
            .unwrap();

        assert_eq!(row.0, 3);
    }

    #[tokio::test]
    async fn test_binary_data() {
        let (_tmp, backend) = setup().await;

        let binary_data: Vec<u8> = (0..=255).collect();
        backend.put("binary", &binary_data).await.unwrap();

        let result = backend.get("binary").await.unwrap();
        assert_eq!(result, Some(binary_data));
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let tmp = TempDir::new().unwrap();

        let backend_a = SqliteBackend::open(tmp.path(), "tenant-a").await.unwrap();
        let backend_b = SqliteBackend::open(tmp.path(), "tenant-b").await.unwrap();

        backend_a.put("shared-key", b"value-a").await.unwrap();
        backend_b.put("shared-key", b"value-b").await.unwrap();

        // Each tenant sees only their own data
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
