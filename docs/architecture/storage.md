# Storage Architecture

This document describes Egide's storage layer architecture.

## Overview

> **Storage backend selection is planned, not implemented yet.** `egide-server` always uses its bundled SQLite backend today; there is no flag, environment variable, or configuration file to select PostgreSQL at runtime, even though the `egide-storage-postgres` crate exists in the workspace and is unit-tested. See [Configuration](../getting-started/configuration.md#storage-backend). The rest of this page describes the trait-based abstraction and the target architecture.

Egide uses a pluggable storage backend architecture:

```text
┌─────────────────────────────────────────────────────────────────┐
│                         EGIDE ENGINES                            │
│        Secrets │ KMS │ PKI │ Transit │ Auth │ Audit             │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ┌────────────▼────────────┐
                │   Storage Abstraction   │
                │      (Trait-based)      │
                └────────────┬────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │PostgreSQL│        │  SQLite │         │ (Future)│
    │ Backend │         │ Backend │         │  S3/... │
    └─────────┘         └─────────┘         └─────────┘
```

## Storage Trait

```rust
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Get a value by key.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Put a value with a key.
    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Delete a value by key.
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// List keys with a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;

    /// Check if a key exists (default implementation calls `get`).
    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        Ok(self.get(key).await?.is_some())
    }
}
```

## PostgreSQL Backend

### Use Case

- Production deployments
- High availability requirements
- Multi-instance deployments

### Features

| Feature | Support |
|---------|---------|
| ACID Transactions | ✅ |
| Connection Pooling | ✅ |
| Replication | ✅ (Native) |
| Point-in-time Recovery | ✅ |
| JSON Queries | ✅ |

### Schema

```sql
-- Each tenant gets its own Postgres schema; every query qualifies its table
-- with that schema (see `egide-storage-postgres`).
CREATE TABLE IF NOT EXISTS "<tenant_schema>".kv_store (
    key        TEXT PRIMARY KEY,
    value      BYTEA NOT NULL,
    version    BIGINT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS "<tenant_schema>".kv_history (
    id        BIGSERIAL PRIMARY KEY,
    key       TEXT NOT NULL,
    value     BYTEA,
    version   BIGINT NOT NULL,
    operation TEXT NOT NULL,
    actor     TEXT
);
```

There is no audit log table; a tamper-evident audit log is planned for 0.2.0, not implemented yet.

### Configuration

> **Status: planned, not implemented yet.** No flag, environment variable, or configuration file exists today to point `egide-server` at a PostgreSQL instance. The parameters above (host, port, pool size, SSL mode) describe the target configuration surface once runtime storage selection ships.

### High Availability

```text
                    ┌─────────────────┐
                    │  Load Balancer  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │ Egide 1 │         │ Egide 2 │         │ Egide 3 │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
                             │
                    ┌────────▼────────┐
                    │    PgBouncer    │
                    │   (Pooling)     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
         │   PG    │───>│   PG    │───>│   PG    │
         │ Primary │    │ Replica │    │ Replica │
         └─────────┘    └─────────┘    └─────────┘
```

## SQLite Backend

### SQLite Use Case

- Development and testing
- Single-node deployments
- Standalone/embedded mode

### SQLite Features

| Feature | Support |
|---------|---------|
| ACID Transactions | ✅ |
| Zero Configuration | ✅ |
| File-based | ✅ |
| In-memory Mode | ✅ |
| Backup | ✅ (File copy) |

### SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS kv_store (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kv_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    key       TEXT NOT NULL,
    value     BLOB,
    version   INTEGER NOT NULL,
    operation TEXT NOT NULL
);
```

Each tenant (secrets, `system` for seal state, `transit`) gets its own SQLite file under the data directory, rather than a shared file with per-tenant rows.

### SQLite Configuration

The only configuration surface is the data directory, set via `--data-dir` or `EGIDE_DATA_DIR` (default `./data`); see [Configuration](../getting-started/configuration.md). Egide opens one SQLite file per internal engine under that directory (for example `system.db` for seal state, `transit.db` for the Transit engine, and one file per secrets tenant). There is no per-file tuning surface (journal mode, cache size, busy timeout) exposed today.

### WAL Mode Benefits

> Egide does not set a journal mode pragma today; each SQLite file uses SQLite's own default. The diagram below illustrates the general benefit WAL mode would bring if configured.

```text
Without WAL:
Writer blocks readers, readers block writers

With WAL:
┌────────────┐     ┌────────────┐
│   Writer   │     │  Readers   │
│            │     │            │
│  [Write]───┼────>│  [Read]    │  Concurrent!
│            │     │  [Read]    │
└────────────┘     └────────────┘
```

## Data Encryption

All data is encrypted before storage:

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Plaintext  │────>│  Encrypted  │────>│   Storage   │
│    Data     │     │    Data     │     │   Backend   │
└─────────────┘     └─────────────┘     └─────────────┘
        │                   ▲
        │                   │
        └───────────────────┘
              Crypto Core
             (AES-256-GCM)
```

### Encryption Key Hierarchy

```text
                    ┌─────────────────┐
                    │   Master Key    │
                    │  (from unseal)  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Encryption Key │
                    │    (derived)    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
         │  DEK 1  │    │  DEK 2  │    │  DEK N  │
         │(per-key)│    │(per-key)│    │(per-key)│
         └─────────┘    └─────────┘    └─────────┘
```

## Backup and Recovery

### SQLite (the backend used today)

```bash
# Stop the server first, then copy the whole data directory
cp -r /var/lib/egide /backup/egide-$(date +%Y%m%d)
```

There is no `egide operator backup` or `egide operator restore` command; back up the data directory directly.

### PostgreSQL

> **Status: planned, not implemented yet.** Once the PostgreSQL backend is wired into `egide-server`, standard `pg_dump`/`pg_restore` would apply.

## Performance Tuning

> **Status: planned, not implemented yet.** There is no connection-pool, statement-timeout, or SQLite-pragma tuning surface exposed today; both backends run with their library defaults.

## Monitoring

> **Status: planned, not implemented yet.** Egide does not expose storage metrics or a `/metrics` endpoint. `GET /v1/sys/health` returns `{"status", "version", "initialized", "sealed", "uptime_secs"}`; it has no `storage` sub-object.

## Future Backends

Planned storage backends:

| Backend | Use Case | Status |
|---------|----------|--------|
| SQLite | Development, the only backend the server runs today | ✅ Available |
| PostgreSQL | Production, clustering | Crate implemented, not wired into `egide-server` yet |
| S3 | Cloud-native | 🔜 Planned |
| Consul | Service mesh | 🔜 Planned |
| etcd | Kubernetes | 🔜 Planned |

## Next Steps

- [Deployment Guide](../deployment/overview.md)
- [Backup & Recovery](../guides/backup.md)
- [High Availability](../guides/high-availability.md)
