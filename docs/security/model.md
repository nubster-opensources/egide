# Security Model

This document describes Egide's security architecture and threat model.

## Overview

Egide is designed with defense-in-depth principles:

1. **Encryption at rest**: All data is encrypted before storage (implemented)
2. **Encryption in transit**: TLS terminated at a reverse proxy in front of Egide; server-side TLS is planned, not implemented yet
3. **Access control**: bearer-token authentication with root-only gating for administrative operations (implemented); path-based policies are planned
4. **Audit logging**: planned for 0.2.0, not implemented yet
5. **Seal/Unseal**: Master key protection (implemented)

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Unauthorized access | Authentication + root-only authorization (path-based policies planned) |
| Data theft at rest | AES-256-GCM encryption |
| Data theft in transit | TLS at the reverse proxy (server-side TLS planned) |
| Privilege escalation | Root/non-root separation today; least privilege policies planned |
| Insider threats | Separation of duties on unseal shares; audit logging planned for 0.2.0 |
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
| Data encryption | AES-256-GCM (Transit also offers ChaCha20-Poly1305 keys) |
| Datakey wrapping | AES-256-GCM (under the transit key) |
| Signatures | Planned with the KMS engine (0.3.0): Ed25519, ECDSA, RSA-PSS |
| Key derivation | HKDF-SHA256 |
| Token hashing | Argon2id (root token hash at rest) |
| Random generation | OS CSPRNG |

## Seal/Unseal Mechanism

### Sealed State

When sealed:

- Master key not in memory
- All data inaccessible
- Only system endpoints respond (health, status, init, unseal); secrets and transit return `503`
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
- Memory cleared on seal

## Access Control

Today, authorization is a binary root/non-root distinction: administrative operations (init, seal, transit key management, service token management) require the root token; secrets and transit data operations are open to any authenticated token (root or service token).

### Policy-Based Authorization

> **Status: planned, not implemented yet.** Path-based, least-privilege policies (path patterns, capabilities, explicit deny) do not exist today; see [Authentication](../concepts/authentication.md#policies). The principles below describe the target model:

- Default deny: No access without explicit policy
- Specific paths: Grant access to specific resources only
- Time-limited tokens: Short TTLs for temporary access

## Authentication Security

### Token Security

- Tokens are cryptographically random
- Service tokens can be revoked immediately (`DELETE /v1/auth/service-tokens/{token_id}`)
- The service token identifier (`token_id`) acts as a non-sensitive reference for listing and revocation without exposing the token
- Token TTLs at creation time are planned, not implemented yet

### AppRole Security

> **Status: planned for 0.2.0, not implemented yet.** Role ID / Secret ID credentials, TTL and use limits, and CIDR binding describe the target design.

### mTLS Security

> **Status: planned, not implemented yet.** Certificate-based mutual authentication is not available today.

## Audit Logging

> **Status: planned for 0.2.0, not implemented yet.** An append-only, HMAC-signed audit log recording every request (timestamp, identity, path, method, status, with sensitive data redacted) is on the roadmap. Today, `tracing` request logs on stdout are the only operational log output; they are not tamper-evident.

## Network Security

### TLS Configuration

Egide does not terminate TLS itself (server-side TLS is planned, not implemented yet); apply these settings at the reverse proxy or load balancer in front of it:

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
| TLS certificates (at the reverse proxy) | 90 days |
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

- Terminate TLS in front of Egide in production
- Rotate keys regularly
- Revoke service tokens that are no longer needed
- Monitor server logs
- Test disaster recovery
- Keep Egide updated

### Don't

- Run in dev mode in production
- Store unseal keys digitally
- Use root token for normal operations
- Expose Egide to public internet
- Ignore server logs
- Skip key rotation

Release builds, including the published Docker image, refuse dev mode by design: there is no way to run dev mode in production, even by mistake. See the [production checklist](../deployment/production-checklist.md).

## Next Steps

- [Compliance](compliance.md): Regulatory compliance
- [Production Deployment](../guides/production.md): Production setup
