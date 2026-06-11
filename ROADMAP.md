# Egide Roadmap

> **Vision**: A modern secrets management platform — secure by design, simple to operate, accessible to all.

---

## Security Philosophy

Egide is a **security-critical** application. Every feature is designed with security as the primary concern.

### Core Security Guarantees

| Guarantee | Implementation |
|-----------|----------------|
| **Encryption at Rest** | AES-256-GCM for all stored data |
| **Encryption in Transit** | TLS 1.3 required (no plaintext API) |
| **Memory Safety** | Rust + zeroize crate for secret cleanup |
| **Zero Trust** | All requests authenticated and authorized |
| **Audit Trail** | Every operation logged for compliance |
| **Defense in Depth** | Multiple layers of protection |

### Threat Model

Egide is designed to protect against:

- **Unauthorized Access**: Strong authentication + fine-grained authorization
- **Data Breach**: Encryption at rest, sealed state when not in use
- **Network Attacks**: TLS required, no sensitive data in URLs
- **Insider Threats**: Audit logs, principle of least privilege
- **Key Compromise**: Key rotation, Shamir's Secret Sharing

---

## Versions

### v0.1.0 - Foundation

**Goal**: A functional vault for managing secrets in development.

#### Storage Layer

- [ ] `StorageBackend` trait (async)
- [ ] SQLite backend implementation
- [ ] Encrypted storage at rest (AES-256-GCM)

#### Crypto Core

- [ ] AES-256-GCM encryption/decryption
- [ ] Key derivation (HKDF-SHA256)
- [ ] Secure random generation (OS CSPRNG)
- [ ] Memory zeroization for sensitive data

#### Secrets Engine

- [ ] CRUD operations (create, read, update, delete)
- [ ] Hierarchical paths (`/{env}/{app}/{secret}`)
- [ ] Secret versioning
- [ ] Soft delete with recovery
- [ ] LIST operation with prefix filtering

#### Seal/Unseal

- [ ] Master key protection
- [ ] Shamir's Secret Sharing (basic)
- [ ] Auto-unseal in dev mode only

#### REST API

- [ ] `GET /v1/secrets/{path}` - Read secret
- [ ] `PUT /v1/secrets/{path}` - Create/Update secret
- [ ] `DELETE /v1/secrets/{path}` - Delete secret
- [ ] `LIST /v1/secrets/{path}` - List secrets
- [ ] TLS required (reject HTTP in production)

#### CLI

- [ ] `egide secrets get <path>`
- [ ] `egide secrets put <path> --value <value>`
- [ ] `egide secrets delete <path>`
- [ ] `egide secrets list [prefix]`
- [ ] `egide operator init`
- [ ] `egide operator unseal`
- [ ] `egide operator seal`

#### Auth (minimal)

- [ ] Root token generation at init
- [ ] Token-based authentication
- [ ] Secure token storage (never logged)

---

### v0.2.0 - Auth & Policies

**Goal**: Multi-user support with granular access control.

#### Token Management

- [ ] Token creation with TTL
- [ ] Token revocation
- [ ] Token renewal
- [ ] Scoped tokens (path restrictions)
- [ ] Token accessor (non-sensitive reference)

#### Policies

- [ ] Policy definition in YAML format
- [ ] Path-based ACL rules with glob patterns
- [ ] Capabilities: `read`, `write`, `delete`, `list`
- [ ] Explicit deny support (deny > allow)
- [ ] Policy assignment to tokens

#### Auth Methods

- [ ] AppRole (machine-to-machine)
- [ ] Userpass (human users)
- [ ] Password hashing (Argon2id)

#### Security Hardening

- [ ] Rate limiting per token/IP
- [ ] Brute-force protection (lockout)
- [ ] Request size limits
- [ ] Timeout configuration

#### Audit

- [ ] Audit log backend trait
- [ ] File audit backend
- [ ] Log format: JSON (HMAC-signed)
- [ ] Events: auth, secret access, policy changes
- [ ] Sensitive data redaction in logs

---

### v0.3.0 - KMS & Transit

**Goal**: Encryption-as-a-Service for applications.

#### KMS Engine

- [ ] Key creation (named keys)
- [ ] Key rotation with versioning
- [ ] Key types: AES-256, RSA-2048/4096, ECDSA-P256, Ed25519
- [ ] Key export (optional, configurable)
- [ ] Key deletion (soft + hard)

#### Transit Engine

- [ ] `POST /v1/transit/encrypt/{key}` - Encrypt data
- [ ] `POST /v1/transit/decrypt/{key}` - Decrypt data
- [ ] `POST /v1/transit/sign/{key}` - Sign data
- [ ] `POST /v1/transit/verify/{key}` - Verify signature
- [ ] `POST /v1/transit/hash` - Hash data
- [ ] `POST /v1/transit/hmac/{key}` - HMAC
- [ ] Batch operations
- [ ] Convergent encryption option

---

### v0.4.0 - PKI

**Goal**: Internal Certificate Authority.

#### CA Management

- [ ] Root CA generation
- [ ] Intermediate CA support
- [ ] CA rotation

#### Certificate Operations

- [ ] Certificate issuance
- [ ] Certificate revocation
- [ ] Certificate renewal

#### Validation

- [ ] CRL (Certificate Revocation List)
- [ ] OCSP responder

#### Templates

- [ ] Server certificate template
- [ ] Client certificate template
- [ ] Code signing template
- [ ] Custom templates

---

### v1.0.0 - Production Ready

**Goal**: Enterprise deployment with stable API.

> ⚠️ **API Stability**: From v1.0.0, the REST API is considered stable. Breaking changes will only occur in major versions.

#### Storage

- [ ] PostgreSQL backend
- [ ] Connection pooling
- [ ] Migrations system
- [ ] Encrypted backups

#### Observability

- [ ] Prometheus metrics endpoint
- [ ] OpenTelemetry tracing
- [ ] Health check endpoints (detailed)
- [ ] Security event metrics

#### Performance

- [ ] gRPC API (with mTLS)
- [ ] Connection multiplexing
- [ ] Caching layer (encrypted)

#### High Availability

- [ ] Leader election
- [ ] Cluster membership
- [ ] State replication (encrypted)
- [ ] Automatic failover

#### Security (Production)

- [ ] mTLS for cluster communication
- [ ] Auto-seal with cloud KMS (AWS/GCP/Azure)
- [ ] Security hardening guide
- [ ] Penetration testing checklist
- [ ] Compliance documentation (SOC2 preparation)

---

## Future Considerations

> Not planned yet. To be evaluated based on demand.

- **Dynamic Secrets**: Database credentials rotation
- **Cloud KMS Integration**: AWS KMS, GCP KMS, Azure Key Vault as backends
- **LDAP/OIDC Auth**: Enterprise identity providers
- **Namespaces**: Multi-tenant isolation
- **Replication**: Cross-datacenter sync
- **HSM Support**: Hardware Security Module integration
- **Web UI**: Administration interface

---

## Design Principles

1. **Security First**: Secure by default, no shortcuts
2. **Simplicity**: Easy to understand, easy to operate
3. **Accessibility**: Quality software at a fair price
4. **Performance**: Rust for speed and memory safety
5. **Observability**: Logs, metrics, traces built-in

---

## Path Structure

```text
/{environment}/{application}/{secret}
```

**Examples:**

```text
/prod/workspace/database-url
/prod/workspace/jwt-secret
/dev/workspace/database-url
/staging/api-gateway/stripe-key
```

---

## Policy Format

Policies are defined in YAML for simplicity and tooling compatibility.

### Policy Structure

```yaml
# policy-name.yaml
name: developer
description: Development environment access for developers

rules:
  # Allow full access to dev environment
  - path: /dev/*
    capabilities: [read, write, delete, list]

  # Read-only access to staging
  - path: /staging/*
    capabilities: [read, list]

  # Explicit deny for production
  - path: /prod/*
    deny: true

  # Specific secret access
  - path: /shared/certificates/public-*
    capabilities: [read]
```

### Capabilities

| Capability | Description |
|------------|-------------|
| `read` | Read secret value |
| `write` | Create or update secret |
| `delete` | Delete secret |
| `list` | List secrets at path |

### Path Patterns

| Pattern | Matches |
|---------|---------|
| `/prod/app/db` | Exact path only |
| `/prod/app/*` | All secrets under `/prod/app/` |
| `/prod/*/db` | `/prod/app/db`, `/prod/api/db`, etc. |
| `/*` | Everything (use with caution) |

### Evaluation Order

1. Explicit `deny: true` rules are evaluated first
2. If any deny matches, access is denied
3. Then allow rules are evaluated
4. If any allow matches, access is granted
5. Default: deny (implicit)

### Built-in Policies

```yaml
# root - Full access (assigned to root token only)
name: root
rules:
  - path: /*
    capabilities: [read, write, delete, list]

# default - No access (assigned when no policy specified)
name: default
rules: []
```

### Example Policies

**CI/CD Pipeline:**

```yaml
name: ci-pipeline
description: Read-only access to production secrets for deployment

rules:
  - path: /prod/*
    capabilities: [read, list]
  - path: /prod/*/admin-*
    deny: true
```

**Application Service:**

```yaml
name: workspace-prod
description: Workspace application production access

rules:
  - path: /prod/workspace/*
    capabilities: [read]
```

**Security Admin:**

```yaml
name: security-admin
description: Manage all secrets except root credentials

rules:
  - path: /*
    capabilities: [read, write, delete, list]
  - path: /*/root-*
    deny: true
  - path: /*/master-*
    deny: true
```
