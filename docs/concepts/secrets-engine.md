# Secrets Engine

The Secrets Engine provides secure storage for sensitive data such as API keys, passwords, certificates, and other secrets.

## Overview

The Secrets Engine is a versioned key/value store with:

- **Versioning** — Keep history of secret changes with rollback capability
- **TTL & Expiration** — Automatic expiration of temporary secrets
- **Metadata** — Custom attributes and tags
- **Rotation** — Manual and automated secret rotation

## Key Concepts

### Paths

Secrets are organized in a hierarchical path structure:

```text
secrets/
├── myapp/
│   ├── database
│   ├── api-key
│   └── config/
│       ├── dev
│       └── prod
└── shared/
    └── encryption-key
```

Path rules:

- Use `/` as separator
- Alphanumeric, hyphens, and underscores allowed
- Case-sensitive
- Maximum depth: 10 levels

### Versions

Every secret update creates a new version:

```json
{
  "path": "myapp/database",
  "current_version": 3,
  "versions": {
    "1": { "created_at": "2025-01-01T00:00:00Z", "deleted": false },
    "2": { "created_at": "2025-01-15T00:00:00Z", "deleted": true },
    "3": { "created_at": "2025-02-01T00:00:00Z", "deleted": false }
  }
}
```

### TTL (Time To Live)

Secrets can have an expiration time:

```bash
# Secret expires in 1 hour
egide secrets put myapp/temp-token token=xxx --ttl=1h
```

After expiration, the secret returns an error when accessed.

## Operations

### Create/Update Secret

```bash
egide secrets put myapp/database \
  username=admin \
  password=supersecret
```

With metadata:

```bash
egide secrets put myapp/database \
  username=admin \
  password=supersecret \
  --metadata="owner=team-a" \
  --metadata="environment=production"
```

### Read Secret

```bash
# Get current version
egide secrets get myapp/database

# Get specific version
egide secrets get myapp/database --version=2
```

### List Secrets

```bash
# List all secrets
egide secrets list

# List secrets under a path
egide secrets list myapp/
```

### Delete Secret

```bash
# Soft delete (marks as deleted, can be recovered)
egide secrets delete myapp/database

# Hard delete (permanent, cannot be recovered)
egide secrets delete myapp/database --permanent
```

### Recover Deleted Secret

```bash
egide secrets recover myapp/database
```

### View Secret History

```bash
egide secrets history myapp/database
```

## Secret Types

### Key/Value (Default)

Standard key-value pairs:

```json
{
  "username": "admin",
  "password": "supersecret",
  "host": "db.example.com"
}
```

### Binary

Base64-encoded binary data:

```bash
egide secrets put myapp/cert --binary @certificate.pem
```

### JSON

Structured JSON data:

```bash
egide secrets put myapp/config --json @config.json
```

## Best Practices

### Path Organization

Organize secrets by application and environment:

```text
secrets/
├── <app-name>/
│   ├── <env>/
│   │   ├── database
│   │   ├── api-keys
│   │   └── config
│   └── shared/
│       └── encryption-key
└── shared/
    └── certificates/
```

### Rotation Strategy

1. **Manual Rotation**: Update secrets via CLI or API
2. **Scheduled Rotation**: Use external automation (cron, CI/CD)
3. **Dynamic Secrets**: Generate on-demand (future feature)

### Access Control

Use policies to restrict access:

```hcl
# Allow read-only access to myapp secrets
path "secrets/myapp/*" {
  capabilities = ["read", "list"]
}

# Allow full access to team-specific secrets
path "secrets/team-a/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

## API Reference

See [Secrets API](../api/secrets.md) for the complete API reference.

## Next Steps

- [KMS Engine](kms-engine.md) — Cryptographic key management
- [Transit Engine](transit-engine.md) — Encryption as a Service
