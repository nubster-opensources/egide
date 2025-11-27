# Storage Architecture

This document describes Egide's storage layer architecture.

## Overview

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
    /// Get a value by key
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Put a value
    async fn put(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Delete a value
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// List keys with prefix
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> Result<bool, StorageError>;

    /// Transaction support
    async fn transaction<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&mut dyn Transaction) -> Result<T, StorageError> + Send;
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
-- Core key-value storage
CREATE TABLE egide_storage (
    key TEXT PRIMARY KEY,
    value BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for prefix queries
CREATE INDEX idx_storage_prefix ON egide_storage (key text_pattern_ops);

-- Audit log
CREATE TABLE egide_audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id UUID,
    operation TEXT NOT NULL,
    path TEXT NOT NULL,
    source_ip INET,
    user_id TEXT,
    request_id UUID,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB
);

CREATE INDEX idx_audit_timestamp ON egide_audit_log (timestamp);
CREATE INDEX idx_audit_tenant ON egide_audit_log (tenant_id, timestamp);
```

### Configuration

```toml
[storage]
type = "postgresql"

[storage.postgresql]
host = "localhost"
port = 5432
database = "egide"
username = "egide"
password_env = "EGIDE_DB_PASSWORD"

# Connection pool
pool_min = 5
pool_max = 20
connection_timeout = "10s"
idle_timeout = "10m"

# SSL
ssl_mode = "require"  # disable, allow, prefer, require, verify-ca, verify-full
ssl_root_cert = "/etc/egide/ca.crt"
```

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

### SQLLite Use Case

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
CREATE TABLE egide_storage (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_storage_prefix ON egide_storage (key);
```

### SQLite Configuration

```toml
[storage]
type = "sqlite"

[storage.sqlite]
path = "/var/lib/egide/egide.db"
# path = ":memory:"  # For in-memory mode

# Performance tuning
journal_mode = "WAL"
synchronous = "NORMAL"
cache_size = 10000
busy_timeout = "5s"
```

### WAL Mode Benefits

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

### PostgreSQL

```bash
# Backup
pg_dump -Fc egide > egide_backup.dump

# Restore
pg_restore -d egide egide_backup.dump
```

### SQLite

```bash
# Backup (while running with WAL)
sqlite3 /var/lib/egide/egide.db ".backup /backup/egide.db"

# Or simple file copy (stop service first)
cp /var/lib/egide/egide.db /backup/
```

### Egide CLI Backup

```bash
# Create encrypted backup
egide operator backup --output /backup/egide-$(date +%Y%m%d).enc

# Restore from backup
egide operator restore --input /backup/egide-20240101.enc
```

## Performance Tuning

### PostgreSQL configuration

```toml
[storage.postgresql]
# Connection pool
pool_max = 50  # Based on: max_connections / egide_instances

# Statement timeout
statement_timeout = "30s"

# Prepared statements
prepare_threshold = 5
```

### SQLite configuration

```toml
[storage.sqlite]
# WAL mode for concurrency
journal_mode = "WAL"

# Larger cache for frequently accessed data
cache_size = 50000  # ~50MB

# Batch writes
synchronous = "NORMAL"  # vs FULL for durability
```

## Monitoring

### Metrics

| Metric | Description |
|--------|-------------|
| `egide_storage_operations_total` | Total storage operations |
| `egide_storage_operation_duration_seconds` | Operation latency |
| `egide_storage_errors_total` | Storage errors |
| `egide_storage_connections_active` | Active connections (PG) |

### Health Check

```http
GET /v1/sys/health

{
  "storage": {
    "type": "postgresql",
    "status": "healthy",
    "latency_ms": 1.2
  }
}
```

## Future Backends

Planned storage backends:

| Backend | Use Case | Status |
|---------|----------|--------|
| PostgreSQL | Production | ✅ Available |
| SQLite | Development | ✅ Available |
| S3 | Cloud-native | 🔜 Planned |
| Consul | Service mesh | 🔜 Planned |
| etcd | Kubernetes | 🔜 Planned |

## Next Steps

- [Deployment Guide](../deployment/overview.md)
- [Backup & Recovery](../guides/backup.md)
- [High Availability](../guides/high-availability.md)
