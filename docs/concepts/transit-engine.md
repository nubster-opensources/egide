# Transit Engine

The Transit Engine provides Encryption as a Service (EaaS), allowing applications to encrypt and decrypt data without managing encryption keys.

## Overview

With Transit Engine, your applications:

- **Never see encryption keys** — Keys stay in Egide
- **Delegate cryptography** — Egide handles all crypto operations
- **Simplify compliance** — Centralized key management and audit

## How It Works

```text
┌─────────────┐                      ┌─────────────┐
│ Application │                      │    Egide    │
└──────┬──────┘                      └──────┬──────┘
       │                                    │
       │  1. Encrypt("sensitive data")      │
       │ ──────────────────────────────────►│
       │                                    │
       │                          ┌─────────▼─────────┐
       │                          │ Encrypt with key  │
       │                          │ (key never leaves │
       │                          │  Egide)           │
       │                          └─────────┬─────────┘
       │                                    │
       │  2. Return ciphertext              │
       │ ◄──────────────────────────────────│
       │                                    │
       │  (Store ciphertext in your DB)     │
       │                                    │
       │  3. Decrypt(ciphertext)            │
       │ ──────────────────────────────────►│
       │                                    │
       │  4. Return plaintext               │
       │ ◄──────────────────────────────────│
```

## Key Concepts

### Named Keys

Transit uses named encryption keys managed in the KMS Engine:

```bash
# Create a transit key
egide kms create payments-key --type aes256
```

### Ciphertext Format

Transit ciphertext includes metadata:

```text
egide:v1:base64-encoded-ciphertext
│     │   │
│     │   └── Encrypted data
│     └────── Key version used
└──────────── Egide prefix
```

### Key Versioning

When you rotate a key:

- New encryptions use the latest version
- Old ciphertext can still be decrypted
- Rewrap upgrades ciphertext to latest version

## Operations

### Encrypt

```bash
# Encrypt data
egide transit encrypt payments-key "credit-card-number"

# Encrypt from file
egide transit encrypt payments-key --input sensitive.txt

# Encrypt with context (for key derivation)
egide transit encrypt payments-key "data" --context "user-123"
```

Output:

```text
egide:v1:AAAAAGVnaWRlAAAAEAAA...
```

### Decrypt

```bash
# Decrypt data
egide transit decrypt payments-key "egide:v1:AAAAA..."

# Decrypt to file
egide transit decrypt payments-key "egide:v1:AAAAA..." --output decrypted.txt

# Decrypt with context
egide transit decrypt payments-key "egide:v1:AAAAA..." --context "user-123"
```

### Rewrap

Upgrade ciphertext to the latest key version without exposing plaintext:

```bash
egide transit rewrap payments-key "egide:v1:AAAAA..."
```

Output:

```text
egide:v3:BBBBB...  (now encrypted with version 3)
```

Use rewrap after key rotation to upgrade stored ciphertext.

### Datakey

Generate a data encryption key for client-side encryption:

```bash
# Generate plaintext + encrypted datakey
egide transit datakey payments-key

# Generate encrypted datakey only (for storage)
egide transit datakey payments-key --no-plaintext
```

Output:

```json
{
  "plaintext": "base64-encoded-key",
  "ciphertext": "egide:v1:encrypted-key"
}
```

**Envelope Encryption Pattern:**

1. Generate datakey
2. Encrypt data locally with plaintext key
3. Store encrypted data + encrypted datakey
4. Discard plaintext key
5. To decrypt: decrypt datakey with Egide, then decrypt data locally

### Batch Operations

Encrypt multiple items in one request:

```bash
egide transit encrypt payments-key --batch items.json
```

`items.json`:

```json
[
  {"plaintext": "item1"},
  {"plaintext": "item2"},
  {"plaintext": "item3"}
]
```

## Use Cases

### Database Encryption

Encrypt sensitive fields before storing:

```python
# Encrypt before save
ciphertext = egide.transit.encrypt("db-key", user.ssn)
db.save(user_id, encrypted_ssn=ciphertext)

# Decrypt after load
row = db.load(user_id)
ssn = egide.transit.decrypt("db-key", row.encrypted_ssn)
```

### API Token Encryption

Encrypt API tokens before logging or storing:

```python
encrypted_token = egide.transit.encrypt("api-key", token)
log.info(f"Token issued: {encrypted_token}")  # Safe to log
```

### File Encryption

Encrypt files using envelope encryption:

```python
# Encrypt
datakey = egide.transit.datakey("file-key")
encrypted_file = aes_encrypt(file_contents, datakey.plaintext)
store(encrypted_file, datakey.ciphertext)

# Decrypt
datakey = egide.transit.decrypt("file-key", stored_ciphertext)
file_contents = aes_decrypt(encrypted_file, datakey)
```

## Performance

### Recommendations

- **Batch requests** for bulk operations
- **Use datakeys** for large data (envelope encryption)
- **Cache datakeys** briefly for high-throughput scenarios

### Benchmarks

| Operation | Latency (p99) |
|-----------|---------------|
| Encrypt (256 bytes) | < 5ms |
| Decrypt (256 bytes) | < 5ms |
| Rewrap | < 5ms |
| Datakey generation | < 10ms |

## Best Practices

### Key per Purpose

Use separate keys for different data types:

```text
payments-encryption-key    → Credit card data
pii-encryption-key         → Personal information
logs-encryption-key        → Sensitive logs
```

### Rotation Strategy

1. Create rotation schedule (e.g., quarterly)
2. Rotate key: `egide kms rotate <key>`
3. Rewrap stored ciphertext in batches
4. Monitor for old version usage

### Context for Multi-Tenancy

Use context to derive tenant-specific keys:

```bash
# Tenant A
egide transit encrypt shared-key "data" --context "tenant-a"

# Tenant B
egide transit encrypt shared-key "data" --context "tenant-b"
```

Same key, different derived keys per tenant.

## API Reference

See [Transit API](../api/transit.md) for the complete API reference.

## Next Steps

- [Secrets Engine](secrets-engine.md) — Secret storage
- [Security Model](../security/model.md) — Security architecture
