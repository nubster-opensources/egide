# Secrets Engine Architecture

The Secrets Engine is responsible for storing and managing sensitive data.

## Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                       SECRETS ENGINE                             │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  Secret Store   │  │  Version Mgr    │  │  TTL Manager    │  │
│  │                 │  │                 │  │                 │  │
│  │  • CRUD ops     │  │  • Versioning   │  │  • Expiration   │  │
│  │  • Path routing │  │  • Rollback     │  │  • Lease mgmt   │  │
│  │  • Metadata     │  │  • History      │  │  • Cleanup      │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                    │            │
│           └────────────────────┼────────────────────┘            │
│                                │                                 │
│                    ┌───────────▼───────────┐                     │
│                    │    Encryption Layer   │                     │
│                    │    (Crypto Core)      │                     │
│                    └───────────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Model

### Secret

```rust
struct Secret {
    path: String,           // Unique path identifier
    current_version: u32,   // Current active version
    metadata: Metadata,     // Secret-level metadata
    versions: Vec<Version>, // All versions
    created_at: DateTime,
    updated_at: DateTime,
}
```

### Version

```rust
struct Version {
    version: u32,           // Version number
    data: EncryptedData,    // Encrypted key-value pairs
    created_at: DateTime,
    deleted_at: Option<DateTime>,
    destruction_time: Option<DateTime>,
}
```

### Metadata

```rust
struct Metadata {
    max_versions: u32,      // Max versions to keep
    cas_required: bool,     // Check-and-set required
    delete_version_after: Duration,
    custom_metadata: Map<String, String>,
}
```

## Path Structure

Secrets are organized in a hierarchical path structure:

```text
secrets/
├── myapp/
│   ├── database          # secrets/myapp/database
│   ├── api-keys          # secrets/myapp/api-keys
│   └── certificates/
│       └── tls           # secrets/myapp/certificates/tls
├── shared/
│   └── encryption-key    # secrets/shared/encryption-key
└── team-a/
    └── credentials       # secrets/team-a/credentials
```

## Version Management

### Version Lifecycle

```text
Version States:
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Created  │────>│  Active  │────>│ Deleted  │────>│Destroyed │
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                      │                                  ▲
                      │          (soft delete)           │
                      └──────────────────────────────────┘
                                 (after TTL)
```

### Version Operations

| Operation | Description |
|-----------|-------------|
| Create | Creates version N+1, sets as current |
| Read | Returns current version data |
| Read (v=N) | Returns specific version data |
| Delete | Soft deletes current version |
| Undelete | Restores soft-deleted version |
| Destroy | Permanently removes version |

## Encryption

### Key Hierarchy

```text
                    ┌─────────────────┐
                    │   Master Key    │
                    │   (Unsealing)   │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   Tenant Key    │
                    │   (Per-tenant)  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │ DEK 1   │         │ DEK 2   │         │ DEK N   │
    │(Secret) │         │(Secret) │         │(Secret) │
    └─────────┘         └─────────┘         └─────────┘
```

### Encryption Process

1. Generate Data Encryption Key (DEK) per secret
2. Encrypt secret data with DEK using AES-256-GCM
3. Encrypt DEK with Tenant Key
4. Store encrypted DEK alongside encrypted data

## TTL and Leases

### TTL Types

| Type | Description |
|------|-------------|
| Secret TTL | Time until secret auto-deletes |
| Version TTL | Time until version is destroyed |
| Lease TTL | Time until access token expires |

### Expiration Flow

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Create    │────>│   Active    │────>│   Expired   │
│   Secret    │     │   (TTL=1h)  │     │  (Cleanup)  │
└─────────────┘     └─────────────┘     └─────────────┘
                          │
                          │ Access
                          ▼
                    ┌─────────────┐
                    │   Lease     │
                    │  (TTL=30m)  │
                    └─────────────┘
```

## Access Control

### Path-Based Policies

```hcl
path "secrets/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secrets/shared/*" {
  capabilities = ["read"]
}

path "secrets/admin/*" {
  capabilities = ["deny"]
}
```

### Capabilities

| Capability | Operation |
|------------|-----------|
| create | Create new secrets |
| read | Read secret data |
| update | Update existing secrets |
| delete | Delete secrets (soft) |
| list | List secret paths |
| destroy | Permanently delete |
| metadata | Manage metadata |

## Performance

### Caching

- **Read Cache** — Recently accessed secrets cached in memory
- **Cache Invalidation** — On write operations
- **TTL-based Eviction** — Automatic cleanup

### Batch Operations

```http
POST /v1/secrets/batch
{
  "operations": [
    { "op": "read", "path": "myapp/db" },
    { "op": "read", "path": "myapp/api" },
    { "op": "write", "path": "myapp/new", "data": {...} }
  ]
}
```

## Storage Schema

### PostgreSQL

```sql
CREATE TABLE secrets (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    path TEXT NOT NULL,
    current_version INT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    UNIQUE(tenant_id, path)
);

CREATE TABLE secret_versions (
    id UUID PRIMARY KEY,
    secret_id UUID REFERENCES secrets(id),
    version INT NOT NULL,
    encrypted_data BYTEA NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    destruction_time TIMESTAMPTZ,
    UNIQUE(secret_id, version)
);

CREATE INDEX idx_secrets_path ON secrets(tenant_id, path);
CREATE INDEX idx_versions_secret ON secret_versions(secret_id, version);
```

## Next Steps

- [KMS Engine Architecture](./kms-engine.md)
- [PKI Engine Architecture](./pki-engine.md)
- [API Reference — Secrets](../api/secrets.md)
