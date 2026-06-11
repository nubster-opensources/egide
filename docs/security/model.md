# Security Model

This document describes Egide's security architecture and threat model.

## Overview

Egide is designed with defense-in-depth principles:

1. **Encryption at rest** — All data is encrypted before storage
2. **Encryption in transit** — TLS for all communications
3. **Access control** — Policy-based authorization
4. **Audit logging** — Complete audit trail
5. **Seal/Unseal** — Master key protection

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Unauthorized access | Authentication + Authorization |
| Data theft at rest | AES-256-GCM encryption |
| Data theft in transit | TLS 1.3 |
| Privilege escalation | Least privilege policies |
| Insider threats | Audit logging, separation of duties |
| Key compromise | Key rotation, versioning |

### Out of Scope

| Threat | Reason |
|--------|--------|
| Physical access to server | Requires physical security |
| Compromise of all unseal key holders | Requires organizational security |
| Side-channel attacks | Requires specialized hardware |
| Zero-day in crypto libraries | Requires upstream fixes |

## Encryption Architecture

### Key Hierarchy

```text
                    ┌─────────────────────┐
                    │    Master Key       │
                    │  (Shamir protected) │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼────────┐ ┌─────▼─────┐ ┌───────▼───────┐
     │ Data Encryption │ │ Key       │ │ Token         │
     │ Key (DEK)       │ │ Encryption│ │ Encryption    │
     └────────┬────────┘ │ Key (KEK) │ │ Key           │
              │          └───────────┘ └───────────────┘
              │
     ┌────────▼────────┐
     │ Encrypted Data  │
     │ (secrets, keys) │
     └─────────────────┘
```

### Master Key Protection

The master key is protected using Shamir's Secret Sharing:

- **Split**: Key divided into N shares
- **Threshold**: K shares required to reconstruct
- **Distribution**: Each share given to different custodian

Example (5 shares, 3 threshold):

- Any 3 of 5 key holders can unseal
- Compromise of 2 shares reveals nothing
- No single person can unseal alone

### Encryption Algorithms

| Purpose | Algorithm |
|---------|-----------|
| Data encryption | AES-256-GCM |
| Key wrapping | AES-256-KWP |
| Signatures | Ed25519, ECDSA P-256/P-384, RSA-PSS |
| Key derivation | HKDF-SHA256 |
| Password hashing | Argon2id |
| Random generation | ChaCha20-based CSPRNG |

## Seal/Unseal Mechanism

### Sealed State

When sealed:

- Master key not in memory
- All data inaccessible
- Only health check endpoints available
- No read/write operations possible

### Unseal Process

1. Administrator provides unseal key share
2. Share validated and stored temporarily
3. When threshold reached, master key reconstructed
4. Master key loaded into memory
5. Data becomes accessible

### Security Properties

- Master key only in memory when unsealed
- Unseal keys never stored on server
- Auto-seal on suspicious activity (optional)
- Memory cleared on seal

## Access Control

### Policy-Based Authorization

Policies define access using path patterns:

```hcl
# Read secrets under myapp/
path "secrets/myapp/*" {
  capabilities = ["read", "list"]
}

# Full access to specific path
path "secrets/admin/config" {
  capabilities = ["create", "read", "update", "delete"]
}

# Deny access
path "secrets/forbidden/*" {
  capabilities = ["deny"]
}
```

### Capabilities

| Capability | Description |
|------------|-------------|
| `create` | Create new resources |
| `read` | Read existing resources |
| `update` | Modify existing resources |
| `delete` | Remove resources |
| `list` | List resources |
| `deny` | Explicitly deny (overrides other rules) |

### Principle of Least Privilege

- Default deny: No access without explicit policy
- Specific paths: Grant access to specific resources only
- Time-limited tokens: Short TTLs for temporary access

## Authentication Security

### Token Security

- Tokens are cryptographically random
- Tokens can have TTL (time-to-live)
- Tokens can be revoked immediately
- Token accessor for management without exposing token

### AppRole Security

- Role ID: Semi-secret (like username)
- Secret ID: Secret (like password), can have TTL and use limits
- CIDR binding: Restrict login by IP address
- Separate credentials for each application

### mTLS Security

- Certificate-based authentication
- Mutual authentication (client and server)
- Certificate revocation checking
- Short-lived certificates recommended

## Audit Logging

### What's Logged

Every request is logged with:

- Timestamp
- Client IP address
- Authentication method and identity
- Requested path and method
- Request parameters (sensitive data redacted)
- Response status
- Duration

### Log Format

```json
{
  "time": "2025-01-15T10:30:00Z",
  "type": "request",
  "auth": {
    "method": "token",
    "accessor": "xxx...",
    "policies": ["admin"]
  },
  "request": {
    "id": "req-123",
    "path": "secrets/myapp/database",
    "method": "GET",
    "client_ip": "10.0.0.5"
  },
  "response": {
    "status": 200
  },
  "duration_ms": 5
}
```

### Log Protection

- Logs are append-only
- Logs can be sent to multiple destinations
- Tamper detection via hashing (optional)
- Log integrity verification

## Network Security

### TLS Configuration

Recommended settings:

- TLS 1.3 only (or TLS 1.2 minimum)
- Strong cipher suites
- Certificate validation
- HSTS headers

### Network Isolation

- Deploy in private network
- Use firewall rules
- Limit exposure to trusted networks
- Consider service mesh for internal traffic

## Operational Security

### Key Ceremony

For production initialization:

1. **Prepare**: Secure room, multiple witnesses
2. **Initialize**: Generate unseal keys
3. **Distribute**: Give each key to different custodian
4. **Verify**: Test unseal process
5. **Document**: Record process (not keys!)

### Rotation Practices

| Component | Frequency |
|-----------|-----------|
| TLS certificates | 90 days |
| Encryption keys | 90-365 days |
| Unseal keys | Annually or on compromise |
| Access tokens | As short as practical |

### Incident Response

On suspected compromise:

1. **Seal** Egide immediately
2. **Revoke** potentially compromised tokens
3. **Rotate** affected keys
4. **Audit** logs for unauthorized access
5. **Investigate** root cause
6. **Unseal** after securing

## Security Recommendations

### Do

- Use TLS in production
- Rotate keys regularly
- Use short-lived tokens
- Monitor audit logs
- Test disaster recovery
- Keep Egide updated

### Don't

- Run in dev mode in production
- Store unseal keys digitally
- Use root token for normal operations
- Expose Egide to public internet
- Ignore audit logs
- Skip key rotation

## Next Steps

- [Compliance](compliance.md) — Regulatory compliance
- [Production Deployment](../guides/production.md) — Production setup
