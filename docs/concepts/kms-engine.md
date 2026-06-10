# KMS Engine

The KMS (Key Management Service) Engine manages cryptographic keys and performs encryption operations.

## Overview

The KMS Engine provides:

- **Key Generation** — Create cryptographic keys (AES, RSA, ECDSA, Ed25519)
- **Key Rotation** — Automatic key versioning with rotation
- **Encrypt/Decrypt** — Symmetric and asymmetric encryption
- **Sign/Verify** — Digital signature operations
- **Key Policies** — Fine-grained access control per key

## Key Types

| Type | Algorithm | Use Cases |
|------|-----------|-----------|
| `aes256` | AES-256-GCM | Symmetric encryption |
| `rsa2048` | RSA 2048-bit | Asymmetric encryption, signing |
| `rsa4096` | RSA 4096-bit | High-security asymmetric operations |
| `ecdsa-p256` | ECDSA P-256 | Digital signatures |
| `ecdsa-p384` | ECDSA P-384 | High-security signatures |
| `ed25519` | Ed25519 | Fast digital signatures |

## Key Lifecycle

```text
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌──────────┐
│ Created │ ──► │ Active  │ ──► │ Rotated  │ ──► │ Disabled │
└─────────┘     └─────────┘     └──────────┘     └──────────┘
                     │                │
                     │                │ (old versions still
                     │                │  decrypt, can't encrypt)
                     ▼                ▼
                ┌──────────────────────────┐
                │      Key Versions        │
                │  v1 → v2 → v3 → v4 ...  │
                └──────────────────────────┘
```

### States

- **Active**: Key can encrypt and decrypt
- **Rotated**: New version created; old versions decrypt only
- **Disabled**: Key cannot be used for any operation
- **Deleted**: Key is permanently removed (soft delete available)

## Operations

### Create Key

```bash
# Create AES-256 key
egide kms create my-encryption-key --type aes256

# Create RSA key for signing
egide kms create my-signing-key --type rsa4096

# Create Ed25519 key
egide kms create my-ed25519-key --type ed25519
```

### List Keys

```bash
egide kms list
```

Output:

```text
NAME                TYPE      VERSION  STATUS
my-encryption-key   aes256    1        active
my-signing-key      rsa4096   2        active
my-ed25519-key      ed25519   1        active
```

### Rotate Key

```bash
egide kms rotate my-encryption-key
```

After rotation:

- New version becomes active for encryption
- Old versions can still decrypt data encrypted with them
- Version number increments

### Encrypt Data

```bash
# Encrypt string
egide kms encrypt my-encryption-key "sensitive data"

# Encrypt file
egide kms encrypt my-encryption-key --input file.txt --output file.enc
```

Output:

```text
egide:v2:AAAAAAAAAAAAAAAA...
```

The ciphertext includes:

- `egide:` — Prefix identifier
- `v2:` — Key version used
- Base64-encoded ciphertext

### Decrypt Data

```bash
# Decrypt string
egide kms decrypt my-encryption-key "egide:v2:AAAAAAA..."

# Decrypt file
egide kms decrypt my-encryption-key --input file.enc --output file.txt
```

### Sign Data

```bash
# Sign data
egide kms sign my-signing-key "data to sign"

# Sign file
egide kms sign my-signing-key --input document.pdf
```

### Verify Signature

```bash
egide kms verify my-signing-key "data to sign" "signature..."
```

### Get Key Info

```bash
egide kms info my-encryption-key
```

Output:

```json
{
  "name": "my-encryption-key",
  "type": "aes256",
  "current_version": 2,
  "versions": [
    { "version": 1, "created_at": "2025-01-01T00:00:00Z", "status": "decrypt-only" },
    { "version": 2, "created_at": "2025-02-01T00:00:00Z", "status": "active" }
  ],
  "created_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-02-01T00:00:00Z"
}
```

## Key Operations Matrix

| Key Type | Encrypt | Decrypt | Sign | Verify |
|----------|---------|---------|------|--------|
| `aes256` | ✅ | ✅ | ❌ | ❌ |
| `rsa2048` | ✅ | ✅ | ✅ | ✅ |
| `rsa4096` | ✅ | ✅ | ✅ | ✅ |
| `ecdsa-p256` | ❌ | ❌ | ✅ | ✅ |
| `ecdsa-p384` | ❌ | ❌ | ✅ | ✅ |
| `ed25519` | ❌ | ❌ | ✅ | ✅ |

## Best Practices

### Key Naming

Use descriptive names with context:

```text
<purpose>-<environment>-<application>

Examples:
- encryption-prod-payments
- signing-staging-api
- auth-dev-tokens
```

### Rotation Policy

- **Symmetric keys**: Rotate every 90 days
- **Asymmetric keys**: Rotate annually or after compromise
- **Signing keys**: Rotate based on signature count or time

### Separation of Duties

- Use different keys for different purposes
- Don't reuse encryption keys for signing
- Separate keys per environment (dev, staging, prod)

## API Reference

See [KMS API](../api/kms.md) for the complete API reference.

## Next Steps

- [Transit Engine](transit-engine.md) — Encryption as a Service
- [PKI Engine](pki-engine.md) — Certificate management
