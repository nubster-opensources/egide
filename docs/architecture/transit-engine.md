# Transit Engine Architecture

The Transit Engine provides Encryption as a Service (EaaS), allowing applications to encrypt and decrypt data without managing encryption keys.

## Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                       TRANSIT ENGINE                             │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │    Encrypt      │  │    Decrypt      │  │    Rewrap       │  │
│  │                 │  │                 │  │                 │  │
│  │  • Single       │  │  • Single       │  │  • Version      │  │
│  │  • Batch        │  │  • Batch        │  │    migration    │  │
│  │  • Convergent   │  │                 │  │  • Key rotation │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                    │            │
│           └────────────────────┼────────────────────┘            │
│                                │                                 │
│  ┌─────────────────────────────▼─────────────────────────────┐  │
│  │                     KMS ENGINE                             │  │
│  │                  (Key Management)                          │  │
│  └─────────────────────────────┬─────────────────────────────┘  │
│                                │                                 │
│                    ┌───────────▼───────────┐                     │
│                    │      Crypto Core      │                     │
│                    │     AES-256-GCM       │                     │
│                    └───────────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Concept

Transit Engine separates **data** from **keys**:

```text
Traditional Approach:
┌─────────────┐     ┌─────────────┐
│ Application │────>│   Key       │  Application manages keys
│             │<────│   Storage   │  High risk of exposure
└─────────────┘     └─────────────┘

Transit Approach:
┌─────────────┐     ┌─────────────┐
│ Application │────>│   EGIDE     │  Keys never leave Egide
│             │<────│   Transit   │  Zero key exposure risk
└─────────────┘     └─────────────┘
```

## Operations

### Encrypt

Encrypt plaintext without exposing the key.

```http
Request:
POST /v1/transit/encrypt/my-key
{
  "plaintext": "c2Vuc2l0aXZlIGRhdGE="  // base64
}

Response:
{
  "ciphertext": "egide:v3:aBcDeFgH..."
}
```

### Decrypt

Decrypt ciphertext using the key version encoded in the ciphertext.

```http
Request:
POST /v1/transit/decrypt/my-key
{
  "ciphertext": "egide:v3:aBcDeFgH..."
}

Response:
{
  "plaintext": "c2Vuc2l0aXZlIGRhdGE="
}
```

### Rewrap

Re-encrypt ciphertext with the latest key version without exposing plaintext.

```http
Request:
POST /v1/transit/rewrap/my-key
{
  "ciphertext": "egide:v1:oldData..."  // v1
}

Response:
{
  "ciphertext": "egide:v5:newData..."  // v5 (latest)
}
```

## Ciphertext Format

The key name is never part of the ciphertext: it is bound in as associated
data during encryption, not encoded in the envelope. AES-256-GCM, the only
algorithm this build implements, keeps the historical short form. Any other
algorithm (currently none is implemented) would use the long form instead.

```text
Short form (AES-256-GCM):
egide:v3:base64-data
  │    │       │
  │    │       └─ Encrypted data (ciphertext + auth tag), base64-encoded
  │    └───────── Key version used
  └────────────── Egide prefix

Long form (any other algorithm):
egide:v3:algorithm:base64-data
  │    │      │         │
  │    │      │         └─ Encrypted data (ciphertext + auth tag), base64-encoded
  │    │      └─────────── Algorithm the data was encrypted under
  │    └────────────────── Key version used
  └─────────────────────── Egide prefix
```

### Format Details

| Component | Description |
|-----------|-------------|
| `egide` | Identifier prefix |
| `v3` | Key version used for encryption (not a ciphertext format version) |
| `algorithm` | Present only in the long form; the base64 alphabet excludes `:`, so the number of `:`-separated segments unambiguously tells short from long form |
| `base64-data` | Base64-encoded encrypted data with nonce |

Both forms are accepted on decryption and checked against the engine's
actual implemented algorithm, never against the key's declared type: a key
created under a type accepted by an earlier release but never implemented
stays decryptable. `encrypt` only ever emits the short form.

## Encryption Modes

### Standard Encryption

- Unique nonce per encryption
- Different ciphertext for same plaintext
- Recommended for most use cases

```text
Encrypt("hello") → "egide:v1:aBc..."
Encrypt("hello") → "egide:v1:xYz..."  // Different!
```

### Convergent Encryption

- Same plaintext produces same ciphertext
- Useful for deduplication, searching encrypted data
- Requires derived key context

```yaml
# Key configuration
name: "search-key"
type: "aes256-gcm"
convergent: true
```

```text
Encrypt("hello", context="user-1") → "egide:v1:aBc..."
Encrypt("hello", context="user-1") → "egide:v1:aBc..."  // Same!
Encrypt("hello", context="user-2") → "egide:v1:xYz..."  // Different context
```

## Datakey Generation

Generate a data encryption key (DEK) for client-side encryption.

### Use Case: Envelope Encryption

```text
┌─────────────┐                    ┌─────────────┐
│ Application │                    │   EGIDE     │
└──────┬──────┘                    └──────┬──────┘
       │                                  │
       │  1. Request datakey              │
       │─────────────────────────────────>│
       │                                  │
       │  2. { plaintext_key,             │
       │       encrypted_key }            │
       │<─────────────────────────────────│
       │                                  │
       │  3. Encrypt large file           │
       │     with plaintext_key           │
       │                                  │
       │  4. Store encrypted_key          │
       │     alongside encrypted file     │
       │                                  │
       │  5. Discard plaintext_key        │
       │                                  │
```

### Datakey API

```http
Request:
POST /v1/transit/datakey/my-key
{
  "type": "plaintext"  // or "wrapped"
}

Response:
{
  "plaintext": "base64-raw-key",      // 32 bytes for AES-256
  "ciphertext": "egide:v3:..."
}
```

## Batch Operations

Process multiple items in a single request.

### Batch Encrypt

```http
Request:
POST /v1/transit/encrypt/my-key
{
  "batch": [
    { "plaintext": "aGVsbG8=" },
    { "plaintext": "d29ybGQ=" },
    { "plaintext": "dGVzdA==" }
  ]
}

Response:
{
  "batch_results": [
    { "ciphertext": "egide:v3:..." },
    { "ciphertext": "egide:v3:..." },
    { "ciphertext": "egide:v3:..." }
  ]
}
```

### Performance

| Mode | Latency | Throughput |
|------|---------|------------|
| Single | ~1ms | 1000/s |
| Batch (100) | ~10ms | 10000/s |

## Key Rotation

Transit automatically handles key rotation:

```text
1. Key rotated (v1 → v2)

2. New encryptions use v2
   Encrypt("data") → "egide:v2:..."

3. Old ciphertext still decrypts
   Decrypt("egide:v1:...") → "data"  ✅

4. Rewrap upgrades to v2
   Rewrap("egide:v1:...") → "egide:v2:..."
```

### Minimum Version Enforcement

```yaml
name: "secure-key"
min_encryption_version: 3  # Only v3+ for new encryptions
min_decryption_version: 2  # v1 ciphertexts rejected
```

## Performance Optimization

### Caching

- Key material cached after first access
- Configurable cache TTL
- Automatic invalidation on rotation

### Connection Pooling

- Persistent connections for high-throughput
- HTTP/2 multiplexing supported
- gRPC for low-latency requirements

## Security Model

### Key Isolation

- Keys never leave Egide
- No key export API for transit keys
- Audit log for all operations

### Access Control

```hcl
path "transit/encrypt/production-*" {
  capabilities = ["update"]
}

path "transit/decrypt/production-*" {
  capabilities = ["update"]
}

path "transit/keys/*" {
  capabilities = ["deny"]  # No key management
}
```

## Use Cases

### Database Field Encryption

```rust
// Before storing
let encrypted = egide.transit.encrypt("db-key", &credit_card)?;
db.insert("credit_card", encrypted);

// When reading
let encrypted = db.get("credit_card");
let credit_card = egide.transit.decrypt("db-key", &encrypted)?;
```

### File Encryption (Envelope)

```rust
// Generate datakey
let datakey = egide.transit.datakey("file-key")?;

// Encrypt file with plaintext key (client-side)
let encrypted_file = aes_encrypt(&file, &datakey.plaintext);

// Store encrypted key with file
store(encrypted_file, datakey.ciphertext);

// Later: decrypt
let datakey = egide.transit.decrypt("file-key", &stored_ciphertext)?;
let file = aes_decrypt(&encrypted_file, &datakey);
```

### Token/Session Encryption

```rust
// Encrypt session data
let token = egide.transit.encrypt("session-key", &session_json)?;

// Decrypt on each request
let session = egide.transit.decrypt("session-key", &token)?;
```

## Next Steps

- [Storage Architecture](./storage.md)
- [API Reference: Transit](../api/transit.md)
- [KMS Engine Architecture](./kms-engine.md)
