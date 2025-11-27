# KMS Engine Architecture

The KMS (Key Management Service) Engine manages cryptographic keys and performs encryption operations.

## Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                         KMS ENGINE                               │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Key Store     │  │  Key Rotation   │  │  Operations     │  │
│  │                 │  │                 │  │                 │  │
│  │  • Create       │  │  • Auto-rotate  │  │  • Encrypt      │  │
│  │  • Import       │  │  • Versioning   │  │  • Decrypt      │  │
│  │  • Export       │  │  • Scheduling   │  │  • Sign/Verify  │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                    │            │
│           └────────────────────┼────────────────────┘            │
│                                │                                 │
│                    ┌───────────▼───────────┐                     │
│                    │      Crypto Core      │                     │
│                    │  AES │ RSA │ ECDSA    │                     │
│                    └───────────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Types

### Supported Algorithms

| Type | Algorithm | Key Sizes | Use Case |
|------|-----------|-----------|----------|
| `aes256-gcm` | AES-256-GCM | 256 bits | Symmetric encryption |
| `rsa-2048` | RSA | 2048 bits | Encryption, signing |
| `rsa-4096` | RSA | 4096 bits | High-security encryption |
| `ecdsa-p256` | ECDSA P-256 | 256 bits | Digital signatures |
| `ecdsa-p384` | ECDSA P-384 | 384 bits | Digital signatures |
| `ed25519` | Ed25519 | 256 bits | Digital signatures |

### Key Properties

```rust
struct Key {
    name: String,
    key_type: KeyType,
    current_version: u32,
    min_decryption_version: u32,
    min_encryption_version: u32,
    deletion_allowed: bool,
    exportable: bool,
    allow_plaintext_backup: bool,
    versions: Vec<KeyVersion>,
    created_at: DateTime,
    updated_at: DateTime,
}

struct KeyVersion {
    version: u32,
    key_material: EncryptedKeyMaterial,
    created_at: DateTime,
}
```

## Key Lifecycle

### State Machine

```text
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Created  │────>│  Active  │────>│ Disabled │────>│ Destroyed│
└──────────┘     └──────────┘     └──────────┘     └──────────┘
                      │ ▲               │
                      │ │               │
                      ▼ │               │
                 ┌──────────┐           │
                 │ Rotated  │───────────┘
                 │(v1→v2→vN)│
                 └──────────┘
```

### Lifecycle Operations

| State | Encrypt | Decrypt | Sign | Verify |
|-------|---------|---------|------|--------|
| Active | ✅ | ✅ | ✅ | ✅ |
| Disabled | ❌ | ✅* | ❌ | ✅ |
| Destroyed | ❌ | ❌ | ❌ | ❌ |

*Only for previously encrypted data

## Key Rotation

### Automatic Rotation

```yaml
# Key configuration
name: "my-encryption-key"
type: "aes256-gcm"
rotation:
  enabled: true
  interval: "30d"  # Rotate every 30 days
  retain_versions: 10
```

### Rotation Process

```text
Before Rotation:
┌─────────────────────────┐
│ Key: my-key             │
│ Current Version: 3      │
│ Versions: [1, 2, 3]     │
└─────────────────────────┘

After Rotation:
┌─────────────────────────┐
│ Key: my-key             │
│ Current Version: 4      │
│ Versions: [1, 2, 3, 4]  │
└─────────────────────────┘
```

### Version Selection

| Operation | Version Used |
|-----------|--------------|
| Encrypt | Current version (latest) |
| Decrypt | Version from ciphertext header |
| Sign | Current version |
| Verify | Version from signature |

## Cryptographic Operations

### Encrypt

```text
Input:                         Output:
┌─────────────┐               ┌─────────────────────────────┐
│  Plaintext  │──────────────>│ egide:v1:key:3:base64data   │
└─────────────┘               └─────────────────────────────┘
                                    │    │   │
                                    │    │   └─ Encrypted data
                                    │    └───── Key version
                                    └────────── Format identifier
```

### Decrypt

```text
Input:                              Output:
┌─────────────────────────────┐    ┌─────────────┐
│ egide:v1:key:3:base64data   │───>│  Plaintext  │
└─────────────────────────────┘    └─────────────┘
        │
        └─ Extracts version 3 to decrypt
```

### Sign / Verify

```text
Sign:
┌─────────────┐               ┌─────────────────┐
│    Data     │──────────────>│    Signature    │
└─────────────┘               └─────────────────┘

Verify:
┌─────────────┐ + ┌───────────┐     ┌───────────┐
│    Data     │   │ Signature │────>│ Valid/    │
└─────────────┘   └───────────┘     │ Invalid   │
                                    └───────────┘
```

## Key Import (BYOK)

### Import Process

```text
Customer Key                    Egide
    │                             │
    │  Wrapped Key               │
    │  (encrypted with           │
    │   Egide's public key)      │
    │────────────────────────────>│
    │                             │
    │                             │  Unwrap
    │                             │  Validate
    │                             │  Store
    │                             │
    │     Key Imported           │
    │<────────────────────────────│
```

### Supported Import Formats

- **Raw** — Base64-encoded key material
- **PKCS#8** — For RSA and EC keys
- **JWK** — JSON Web Key format

## Key Export

### Export Controls

| Setting | Description |
|---------|-------------|
| `exportable` | Whether key can be exported |
| `allow_plaintext_backup` | Allow unencrypted export |

### Export Formats

- **Wrapped** — Encrypted with another key
- **JWK** — JSON Web Key (if exportable)

## Key Policies

### Policy Structure

```hcl
path "kms/keys/production/*" {
  capabilities = ["encrypt", "decrypt"]
}

path "kms/keys/signing/*" {
  capabilities = ["sign", "verify"]
}

path "kms/keys/admin/*" {
  capabilities = ["create", "rotate", "delete"]
}
```

### Capabilities

| Capability | Operations Allowed |
|------------|--------------------|
| create | Create new keys |
| read | Read key metadata |
| update | Update key config |
| delete | Delete/destroy keys |
| encrypt | Encrypt data |
| decrypt | Decrypt data |
| sign | Sign data |
| verify | Verify signatures |
| rotate | Trigger key rotation |
| export | Export key material |

## Storage Schema

### PostgreSQL

```sql
CREATE TABLE kms_keys (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    name TEXT NOT NULL,
    key_type TEXT NOT NULL,
    current_version INT NOT NULL DEFAULT 1,
    min_decryption_version INT NOT NULL DEFAULT 1,
    min_encryption_version INT NOT NULL DEFAULT 0,
    deletion_allowed BOOLEAN NOT NULL DEFAULT true,
    exportable BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    UNIQUE(tenant_id, name)
);

CREATE TABLE kms_key_versions (
    id UUID PRIMARY KEY,
    key_id UUID REFERENCES kms_keys(id),
    version INT NOT NULL,
    encrypted_material BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(key_id, version)
);

CREATE INDEX idx_kms_keys_name ON kms_keys(tenant_id, name);
```

## Performance Considerations

### Caching

- Key metadata cached in memory
- Key material loaded on demand
- Version lookups optimized

### Batch Operations

```json
POST /v1/kms/batch
{
  "operations": [
    { "op": "encrypt", "key": "key1", "plaintext": "..." },
    { "op": "encrypt", "key": "key1", "plaintext": "..." },
    { "op": "decrypt", "key": "key1", "ciphertext": "..." }
  ]
}
```

## Next Steps

- [PKI Engine Architecture](./pki-engine.md)
- [Transit Engine Architecture](./transit-engine.md)
- [API Reference — KMS](../api/kms.md)
