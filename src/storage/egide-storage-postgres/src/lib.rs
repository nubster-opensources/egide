//! # Egide Storage - PostgreSQL Backend
//!
//! PostgreSQL implementation of the storage backend with schema-per-tenant
//! isolation. Each tenant gets its own Postgres schema; every query qualifies
//! its tables explicitly, so tenant isolation never depends on session state.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use tracing::{debug, info};

use egide_storage::{StorageBackend, StorageError};

/// PostgreSQL storage backend with schema-per-tenant isolation.
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
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Returns the current actor, if set.
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
    #[allow(dead_code)]
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs() as i64
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        todo!("implemented in Task 3")
    }

    async fn put(&self, _key: &str, _value: &[u8]) -> Result<(), StorageError> {
        todo!("implemented in Task 3")
    }

    async fn delete(&self, _key: &str) -> Result<(), StorageError> {
        todo!("implemented in Task 4")
    }

    async fn list(&self, _prefix: &str) -> Result<Vec<String>, StorageError> {
        todo!("implemented in Task 5")
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    // A bogus URL is fine: validation rejects invalid tenants before the pool
    // is ever opened, so these tests need no Docker.
    const ANY_URL: &str = "postgres://unused:unused@127.0.0.1:1/unused";

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
}
