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

> **Status: planned for 0.2.0, not implemented yet.** The append-only, HMAC-signed
> audit log described below is on the roadmap. Today, `tracing` request logs
> (stdout, filtered by `RUST_LOG`) are the only operational log output; they are
> not append-only, signed, or exportable through the CLI or API.

Once implemented, the audit log is intended to be:

- **Append-only**: entries are written once and never modified.
- **Signed**: each entry carries an HMAC chain anchored to the previous entry,
  making truncation or tampering detectable.
- **Exportable**: for retention in any SIEM or archival system.

Example target log entry:

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

> **Status: planned, not implemented yet.** Egide does not terminate TLS itself; `egide-server` binds to a plain HTTP address. Terminate TLS at a reverse proxy or load balancer placed in front of Egide. See [Production deployment](../guides/production.md#tls).

## Access control

Egide authenticates every request with a bearer token (`Authorization: Bearer <token>`).

- **Root token**: issued once at `POST /v1/sys/init`, with unlimited privileges (administrative operations: init, seal, unseal, transit key management, service token management).
- **Service tokens**: native tokens (`egst_<id>.<secret>`) created and revoked by the root token via `POST` / `GET` / `DELETE /v1/auth/service-tokens`. They can read and write secrets and use existing Transit keys, but cannot perform operator actions or manage other tokens.

> **Status: planned, not implemented yet.** Path-based, least-privilege policies and an external OIDC auth method are not implemented. Today, authorization is a binary root/non-root distinction; there is no policy engine and no `egide policy` command.

## Key lifecycle and rotation

The Transit engine manages cryptographic keys with versioning built in. (The KMS engine referenced elsewhere in this document is planned for 0.3.0 and not implemented yet; see [KMS Engine](../concepts/kms-engine.md).)

- Keys are never exported in plaintext. Applications request encrypt/decrypt
  operations through the Transit engine; the key material never leaves the server.
- Each key has an active version. Older versions are retained for decryption of
  existing ciphertexts.
- Rotation is triggered via the API: `POST /v1/transit/keys/{name}/rotate` (root-only). Rewrap stored ciphertext to the latest version with `POST /v1/transit/rewrap/{name}`.
- Key usage is not yet recorded in a dedicated audit log (see [Audit trail](#audit-trail) above).

## Defense in depth

Egide layers multiple independent controls so that compromise of any single layer
does not expose secret material:

1. **Sealed state at rest** - raw storage is unreadable without the unseal quorum.
2. **Encrypted storage** - individual records are encrypted even within the database.
3. **Authentication** - every API call requires a valid bearer token (root or service token).
4. **Authorization** - root-only operations (init, seal, transit key management, service token management) are checked separately from operations open to any authenticated token.

Path-level, least-privilege policies and a tamper-evident audit log are planned but not implemented yet (see [Access control](#access-control) and [Audit trail](#audit-trail) above).

## Operational checklist

Before going to production, verify the following controls are in place:

- [ ] TLS certificates issued and auto-renewal configured at the reverse proxy in front of Egide (Egide does not terminate TLS itself)
- [ ] Unseal shares distributed to separate operators (minimum quorum required)
- [ ] Service tokens provisioned per consuming application; root token usage limited to administrative operations
- [ ] Encryption at rest verified (storage backend, deployment region documented)
- [ ] Key rotation schedule defined and tested

## Next steps

- [Security model](model.md): threat model and security guarantees
- [Production deployment](../guides/production.md): secure deployment guide
