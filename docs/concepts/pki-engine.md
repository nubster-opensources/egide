# PKI Engine

The PKI (Public Key Infrastructure) Engine provides an internal Certificate Authority for managing TLS/mTLS certificates.

## Overview

The PKI Engine enables you to:

- **Create Certificate Authorities** — Root and Intermediate CAs
- **Issue Certificates** — TLS server, client, and code signing certificates
- **Manage Certificate Lifecycle** — Renewal, revocation, expiration
- **Certificate Templates** — Predefined profiles for common use cases

## Key Concepts

### Certificate Hierarchy

```text
┌─────────────────────────┐
│       Root CA           │  ← Long-lived, offline storage recommended
└───────────┬─────────────┘
            │
┌───────────▼─────────────┐
│   Intermediate CA       │  ← Used for day-to-day signing
└───────────┬─────────────┘
            │
    ┌───────┼───────┐
    │       │       │
┌───▼──┐ ┌──▼──┐ ┌──▼──┐
│Server│ │Client│ │Code │  ← End-entity certificates
│ Cert │ │ Cert │ │Sign │
└──────┘ └──────┘ └─────┘
```

### Certificate Templates

| Template | Purpose | Key Usage |
|----------|---------|-----------|
| `server` | TLS server authentication | Digital Signature, Key Encipherment |
| `client` | TLS client authentication | Digital Signature |
| `code-signing` | Code and document signing | Digital Signature |
| `intermediate-ca` | Intermediate CA certificate | Certificate Sign, CRL Sign |

## Operations

### Initialize Root CA

```bash
egide pki init-ca \
  --cn "My Organization Root CA" \
  --org "My Organization" \
  --country "FR" \
  --validity 10y
```

This creates a self-signed Root CA. Store the Root CA securely.

### Create Intermediate CA

```bash
egide pki create-intermediate \
  --cn "My Organization Intermediate CA" \
  --org "My Organization" \
  --validity 5y
```

### Issue Server Certificate

```bash
egide pki issue \
  --template server \
  --cn "api.example.com" \
  --san "api.example.com,api-internal.example.com" \
  --validity 90d
```

Output:

```text
Certificate issued successfully.

Serial Number: 1234567890
Subject: CN=api.example.com
Valid From: 2025-01-15T00:00:00Z
Valid To: 2025-04-15T00:00:00Z

Certificate saved to: ./api.example.com.crt
Private key saved to: ./api.example.com.key
```

### Issue Client Certificate

```bash
egide pki issue \
  --template client \
  --cn "service-account@example.com" \
  --validity 365d
```

### List Certificates

```bash
egide pki list
```

Output:

```text
SERIAL        CN                      EXPIRES      STATUS
1234567890    api.example.com         2025-04-15   valid
1234567891    service-account@...     2026-01-15   valid
1234567892    old-service.example.com 2025-01-01   expired
```

### Revoke Certificate

```bash
egide pki revoke 1234567890 --reason key-compromise
```

Revocation reasons:

- `unspecified`
- `key-compromise`
- `ca-compromise`
- `affiliation-changed`
- `superseded`
- `cessation-of-operation`

### Get Certificate

```bash
# Get certificate by serial number
egide pki get 1234567890

# Get certificate chain
egide pki get 1234567890 --chain
```

### Renew Certificate

```bash
egide pki renew 1234567890
```

### Generate CRL

```bash
egide pki crl
```

## Certificate Profiles

### Server Certificate

```yaml
template: server
key_type: ecdsa-p256
validity: 90d
key_usage:
  - digital_signature
  - key_encipherment
extended_key_usage:
  - server_auth
```

### Client Certificate

```yaml
template: client
key_type: ecdsa-p256
validity: 365d
key_usage:
  - digital_signature
extended_key_usage:
  - client_auth
```

### mTLS (Mutual TLS)

For mTLS, you need both server and client certificates:

```bash
# Server certificate
egide pki issue --template server --cn "api.example.com"

# Client certificate
egide pki issue --template client --cn "client-app"
```

## Auto-Renewal

Configure automatic certificate renewal before expiration:

```toml
[pki.auto_renewal]
enabled = true
# Renew when less than 30 days remaining
threshold = "30d"
# Check interval
interval = "24h"
```

## Best Practices

### CA Security

1. **Protect Root CA**: Keep Root CA offline or in HSM
2. **Use Intermediate CA**: Issue certificates from Intermediate CA only
3. **Short-Lived Certificates**: Prefer 90-day validity for server certs
4. **Automate Renewal**: Use auto-renewal to prevent expiration

### Certificate Management

1. **Inventory**: Keep track of all issued certificates
2. **Monitor Expiration**: Set up alerts for expiring certificates
3. **Revoke Promptly**: Revoke compromised certificates immediately
4. **Audit**: Review certificate issuance logs regularly

### Key Storage

1. **Never Share Private Keys**: Each service gets its own certificate
2. **Secure Key Files**: Set proper file permissions (600)
3. **Rotate on Compromise**: Issue new certificate if key is compromised

## API Reference

See [PKI API](../api/pki.md) for the complete API reference.

## Next Steps

- [Transit Engine](transit-engine.md) — Encryption as a Service
- [Security Model](../security/model.md) — Security architecture
