# Roadmap

> **Vision**: a modern secrets management platform, secure by design, simple to
> operate, accessible to all.

This is the single source of truth for the planned features and milestones of
egide. Every feature is designed with security as the primary concern: for the
detailed threat model and guarantees, see the [security model](../security/model.md).

## Milestones at a glance

| Version | Theme | Status |
| --- | --- | --- |
| 0.1.0 | Foundation: crypto core, secrets engine, seal and unseal, REST and gRPC, SQLite and PostgreSQL | released |
| 0.2.0 | Auth and policies: token management, YAML ACLs, AppRole, audit log | planned |
| 0.3.0 | KMS and Transit: named keys, rotation, encryption as a service | planned |
| 0.4.0 | PKI: internal CA, certificate issuance and revocation | planned |
| 1.0.0 | Production ready: high availability, observability, stable API | planned |

## Design principles

1. **Security first.** Secure by default, with no shortcuts.
2. **Simplicity.** Easy to understand, easy to operate.
3. **No lock-in.** Plain REST and gRPC, hierarchical paths, YAML policies.
4. **Memory safety.** Rust with zeroization for all sensitive data.
5. **Observability.** Logs, metrics, and traces built in.

---

## 0.1.0 - Foundation (released)

**Goal**: a functional secrets store for managing secrets in development.

### Storage

- [x] `StorageBackend` trait (async)
- [x] SQLite backend
- [x] PostgreSQL backend
- [x] Encrypted storage at rest (AES-256-GCM)

### Crypto core

- [x] AES-256-GCM encryption and decryption
- [x] Key derivation (HKDF-SHA256), bound to secret path and version
- [x] Secure random generation (OS CSPRNG)
- [x] Memory zeroization for sensitive data

### Secrets engine

- [x] CRUD operations (create, read, update, delete)
- [x] Hierarchical paths (`/{env}/{app}/{secret}`)
- [x] Secret versioning
- [x] Soft delete with recovery
- [x] LIST operation with prefix filtering

### Seal and unseal

- [x] Master key protection
- [x] Shamir's Secret Sharing (basic)
- [x] Auto-unseal in dev mode only, gated behind an explicit environment guard

### REST and gRPC API

- [x] `GET /v1/secrets/{path}` - read secret
- [x] `PUT /v1/secrets/{path}` - create or update secret
- [x] `DELETE /v1/secrets/{path}` - delete secret
- [x] `LIST /v1/secrets/{path}` - list secrets
- [x] Transit encrypt and decrypt over HTTP
- [x] gRPC transport alongside REST

### CLI

- [x] `egide secrets get <path>`
- [x] `egide secrets put <path> --value <value>`
- [x] `egide secrets delete <path>`
- [x] `egide secrets list [prefix]`
- [x] `egide operator init`
- [x] `egide operator unseal`
- [x] `egide operator seal`

### Auth (minimal)

- [x] Root token generation at init
- [x] Native token authentication (required at boot, OIDC optional)
- [x] Secure token storage (never logged)

---

## 0.2.0 - Auth and policies (planned)

**Goal**: multi-user support with granular access control.

### Token management

- [ ] Token creation with TTL
- [ ] Token revocation
- [ ] Token renewal
- [ ] Scoped tokens (path restrictions)
- [ ] Token accessor (non-sensitive reference)

### Policies

- [ ] Policy definition in YAML format
- [ ] Path-based ACL rules with glob patterns
- [ ] Capabilities: `read`, `write`, `delete`, `list`
- [ ] Explicit deny support (deny wins over allow)
- [ ] Policy assignment to tokens

### Auth methods

- [ ] AppRole (machine to machine)
- [ ] Userpass (human users)
- [ ] Password hashing (Argon2id)

### Security hardening

- [ ] Rate limiting per token and per IP
- [ ] Brute-force protection (lockout)
- [ ] Request size limits
- [ ] Timeout configuration

### Audit

- [ ] Audit log backend trait
- [ ] File audit backend
- [ ] Log format: JSON (HMAC-signed)
- [ ] Events: auth, secret access, policy changes
- [ ] Sensitive data redaction in logs

---

## 0.3.0 - KMS and Transit (planned)

**Goal**: encryption as a service for applications.

> The transit engine already exposes encrypt and decrypt in 0.1.0. This milestone
> completes the cryptographic operations surface and adds the KMS engine.

### KMS engine

- [ ] Key creation (named keys)
- [ ] Key rotation with versioning
- [ ] Key types: AES-256, RSA-2048/4096, ECDSA-P256, Ed25519
- [ ] Key export (optional, configurable)
- [ ] Key deletion (soft and hard)

### Transit engine

- [ ] `POST /v1/transit/sign/{key}` - sign data
- [ ] `POST /v1/transit/verify/{key}` - verify signature
- [ ] `POST /v1/transit/hash` - hash data
- [ ] `POST /v1/transit/hmac/{key}` - HMAC
- [ ] Batch operations
- [ ] Convergent encryption option

---

## 0.4.0 - PKI (planned)

**Goal**: internal Certificate Authority.

### CA management

- [ ] Root CA generation
- [ ] Intermediate CA support
- [ ] CA rotation

### Certificate operations

- [ ] Certificate issuance
- [ ] Certificate revocation
- [ ] Certificate renewal

### Validation

- [ ] CRL (Certificate Revocation List)
- [ ] OCSP responder

### Templates

- [ ] Server, client, and code-signing certificate templates
- [ ] Custom templates

---

## 1.0.0 - Production ready (planned)

**Goal**: stable, production-ready deployment with high availability.

> **API stability**: from 1.0.0, the REST API is considered stable. Breaking
> changes only occur in major versions.

### Storage

- [ ] Connection pooling
- [ ] Migrations system
- [ ] Encrypted backups

### Observability

- [ ] Prometheus metrics endpoint
- [ ] OpenTelemetry tracing
- [ ] Detailed health check endpoints
- [ ] Security event metrics

### Performance

- [ ] mTLS on the gRPC API
- [ ] Connection multiplexing
- [ ] Encrypted caching layer

### High availability

- [ ] Leader election
- [ ] Cluster membership
- [ ] Encrypted state replication
- [ ] Automatic failover

### Security (production)

- [ ] mTLS for cluster communication
- [ ] Auto-seal with cloud KMS backends
- [ ] Security hardening guide
- [ ] Penetration testing checklist
- [ ] Compliance documentation

---

## Future considerations

Items not yet scheduled, to be evaluated based on community feedback:

- Dynamic secrets (database credential rotation)
- Cloud KMS integration as a backend seal provider
- LDAP and OIDC authentication methods
- Multi-tenant namespaces
- Cross-datacenter replication
- HSM support
- Web administration UI

---

## Reference: path structure

Secrets are organised as a hierarchy:

```text
/{environment}/{application}/{secret}
```

Examples:

```text
/prod/workspace/database-url
/prod/workspace/jwt-secret
/dev/workspace/database-url
/staging/api-gateway/payment-key
```

## Reference: policy format (planned for 0.2.0)

Policies are defined in YAML for simplicity and tooling compatibility. This
format is a design preview: the policy engine ships in 0.2.0.

```yaml
# policy-name.yaml
name: developer
description: Development environment access for developers

rules:
  # Full access to the dev environment
  - path: /dev/*
    capabilities: [read, write, delete, list]

  # Read-only access to staging
  - path: /staging/*
    capabilities: [read, list]

  # Explicit deny for production
  - path: /prod/*
    deny: true
```

### Capabilities

| Capability | Description |
| --- | --- |
| `read` | Read secret value |
| `write` | Create or update secret |
| `delete` | Delete secret |
| `list` | List secrets at path |

### Path patterns

| Pattern | Matches |
| --- | --- |
| `/prod/app/db` | Exact path only |
| `/prod/app/*` | All secrets under `/prod/app/` |
| `/prod/*/db` | `/prod/app/db`, `/prod/api/db`, and so on |
| `/*` | Everything (use with caution) |

### Evaluation order

1. Explicit `deny: true` rules are evaluated first.
2. If any deny matches, access is denied.
3. Allow rules are evaluated next.
4. If any allow matches, access is granted.
5. Default: deny (implicit).
