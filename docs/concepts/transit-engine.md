# Transit Engine

The Transit Engine provides Encryption as a Service (EaaS), allowing applications to encrypt and decrypt data without managing encryption keys.

## Overview

With Transit Engine, your applications:

- **Never see encryption keys**: Keys stay in Egide
- **Delegate cryptography**: Egide handles all crypto operations
- **Simplify compliance**: Centralized key management and audit

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

Transit manages its own named encryption keys directly (there is no dependency on the KMS engine, which is a separate, not-yet-implemented engine; see [KMS Engine](kms-engine.md)). Create a key through the REST API (root token required):

```bash
curl -s -X POST http://localhost:8200/v1/transit/keys \
  -H "Authorization: Bearer <root-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "payments-key", "type": "aes256-gcm"}'
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

All Transit operations are reached through the REST API (or the equivalent gRPC calls); there is no CLI support for Transit today. Plaintext is always base64-encoded in requests and responses.

### Encrypt

```bash
curl -s -X POST http://localhost:8200/v1/transit/encrypt/payments-key \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "'"$(echo -n "credit-card-number" | base64)"'"}'
```

Output:

```json
{"ciphertext": "egide:v1:AAAAAGVnaWRlAAAAEAAA..."}
```

### Decrypt

```bash
curl -s -X POST http://localhost:8200/v1/transit/decrypt/payments-key \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "egide:v1:AAAAA..."}'
```

Output:

```json
{"plaintext": "base64-encoded-data"}
```

### Rewrap

Upgrade ciphertext to the latest key version without exposing plaintext:

```bash
curl -s -X POST http://localhost:8200/v1/transit/rewrap/payments-key \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext": "egide:v1:AAAAA..."}'
```

Output:

```json
{"ciphertext": "egide:v3:BBBBB..."}
```

Use rewrap after key rotation to upgrade stored ciphertext.

### Datakey

Generate a data encryption key for client-side encryption:

```bash
curl -s -X POST http://localhost:8200/v1/transit/datakey/payments-key \
  -H "Authorization: Bearer <token>"
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

> **Status: planned, not implemented yet.** Batch operations (encrypting multiple items in one request), key derivation `context`, and file-based input/output are not implemented. Each Transit call handles one plaintext or ciphertext value.

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
2. Rotate key: `POST /v1/transit/keys/<key>/rotate` (root-only)
3. Rewrap stored ciphertext one at a time with `POST /v1/transit/rewrap/<key>`
4. Monitor for old version usage

### Context for Multi-Tenancy

> **Status: planned, not implemented yet.** Key-derivation `context` is not implemented; use a separate named key per tenant instead.

## API Reference

See [Transit API](../api/transit.md) for the complete API reference.

## Next Steps

- [Secrets Engine](secrets-engine.md): Secret storage
- [Security Model](../security/model.md): Security architecture
