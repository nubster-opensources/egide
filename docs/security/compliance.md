# Security controls

This page describes the technical security controls built into Egide. These controls
address common requirements around data residency, audit integrity, encryption,
access management, and key lifecycle.

## Data residency

Egide is fully self-hostable. All secret material, keys, and audit records remain
within the infrastructure you operate. Nothing is transmitted to external services.

- Deploy on any host, region, or private network you control.
- No telemetry or call-home traffic is emitted by the server.
- Storage backends (SQLite, PostgreSQL) run inside your own environment.

## Audit trail

Every operation that touches Egide produces a structured log entry. The audit log is:

- **Append-only**: entries are written once and never modified.
- **Signed**: each entry carries an HMAC chain anchored to the previous entry,
  making truncation or tampering detectable.
- **Exportable**: the `egide audit report` command exports logs in JSON or CSV
  for retention in any SIEM or archival system.

Example log entry:

```json
{
  "time": "2025-01-15T10:30:00Z",
  "type": "request",
  "operation": "read",
  "path": "secrets/patient/record-123",
  "user": "dr.smith",
  "client_ip": "10.0.0.5",
  "success": true
}
```

Retention period is configured at deployment time. See
[Production deployment](../guides/production.md) for log forwarding guidance.

## Encryption at rest and in transit

### At rest

All secrets and key material are encrypted before being written to storage.

| Layer | Algorithm | Notes |
|-------|-----------|-------|
| Secret values | AES-256-GCM | Per-secret key derived from the master key |
| Master key | Shamir's Secret Sharing | Split across operator shares; never stored in one piece |
| Key versions | AES-256-GCM | Each key version encrypted independently |

A sealed server holds no usable key material in memory. After a restart, the server
refuses all operations until a quorum of operators provides their unseal shares.

### In transit

All API endpoints are served over TLS. Plaintext HTTP is not supported in production
mode. Minimum TLS version and cipher suite configuration are described in
[Production deployment](../guides/production.md).

## Access control

Egide enforces policy-based access control on every request.

- **Token authentication**: clients present a bearer token issued by Egide or an
  external OIDC provider.
- **Path-based policies**: access rules are expressed as YAML documents that bind
  a principal to a set of allowed operations on a path prefix.
- **Least privilege by default**: new tokens have no capabilities unless a policy
  explicitly grants them.
- **Role separation**: administrative operations (unseal, policy management) require
  a separate token with elevated capabilities.

Export the full policy matrix at any time:

```bash
egide policy export --format markdown
```

## Key lifecycle and rotation

The KMS and Transit engines manage cryptographic keys with versioning built in.

- Keys are never exported in plaintext. Applications request encrypt/decrypt/sign
  operations; the key material never leaves the server.
- Each key has an active version. Older versions are retained for decryption of
  existing ciphertexts and can be revoked individually.
- Rotation is manual (triggered by `egide kms rotate`) or scheduled via the API.
- Key usage is recorded in the audit log, providing a complete history per key name.

## Defense in depth

Egide layers multiple independent controls so that compromise of any single layer
does not expose secret material:

1. **Sealed state at rest** - raw storage is unreadable without the unseal quorum.
2. **Encrypted storage** - individual records are encrypted even within the database.
3. **Authentication** - every API call requires a valid, non-expired token.
4. **Authorization** - valid tokens are still subject to path-level policy checks.
5. **Audit log** - all four layers produce tamper-evident log entries.

## Operational checklist

Before going to production, verify the following controls are in place:

- [ ] TLS certificates issued and auto-renewal configured
- [ ] Unseal shares distributed to separate operators (minimum quorum required)
- [ ] Audit log forwarding to durable storage configured
- [ ] Retention period defined for audit logs
- [ ] Access policies scoped to least privilege and peer-reviewed
- [ ] Encryption at rest verified (storage backend, deployment region documented)
- [ ] Key rotation schedule defined and tested

## Next steps

- [Security model](model.md): threat model and security guarantees
- [Production deployment](../guides/production.md): secure deployment guide
