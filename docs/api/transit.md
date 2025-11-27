# Transit API

The Transit API provides Encryption as a Service endpoints.

## Encrypt

Encrypt data without exposing the key.

```http
POST /v1/transit/encrypt/:key_name
```

### Request

```json
{
  "plaintext": "base64-encoded-data",
  "context": "optional-context"
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | string | Base64-encoded plaintext (required) |
| `context` | string | Key derivation context (optional) |

### Response

```json
{
  "data": {
    "ciphertext": "egide:v1:AAAAAAAAAAAAA..."
  }
}
```

### Example

```bash
plaintext=$(echo -n "credit-card-number" | base64)
curl -X POST \
  -H "Authorization: Bearer s.XXXX" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$plaintext\"}" \
  https://egide.example.com/v1/transit/encrypt/payments-key
```

## Decrypt

Decrypt data.

```http
POST /v1/transit/decrypt/:key_name
```

### Decrypt Request

```json
{
  "ciphertext": "egide:v1:AAAAAAAAAAAAA...",
  "context": "optional-context"
}
```

### Decrypt Response

```json
{
  "data": {
    "plaintext": "base64-encoded-data"
  }
}
```

## Batch Encrypt

Encrypt multiple items in one request.

```http
POST /v1/transit/encrypt/:key_name/batch
```

### Batch Encrypt Request

```json
{
  "items": [
    {"plaintext": "base64-item-1"},
    {"plaintext": "base64-item-2"},
    {"plaintext": "base64-item-3"}
  ]
}
```

### Batch Encrypt Response

```json
{
  "data": {
    "results": [
      {"ciphertext": "egide:v1:AAA..."},
      {"ciphertext": "egide:v1:BBB..."},
      {"ciphertext": "egide:v1:CCC..."}
    ]
  }
}
```

## Batch Decrypt

Decrypt multiple items in one request.

```http
POST /v1/transit/decrypt/:key_name/batch
```

### Batch Decrypt Request

```json
{
  "items": [
    {"ciphertext": "egide:v1:AAA..."},
    {"ciphertext": "egide:v1:BBB..."},
    {"ciphertext": "egide:v1:CCC..."}
  ]
}
```

### Batch Decrypt Response

```json
{
  "data": {
    "results": [
      {"plaintext": "base64-item-1"},
      {"plaintext": "base64-item-2"},
      {"plaintext": "base64-item-3"}
    ]
  }
}
```

## Rewrap

Re-encrypt ciphertext with the latest key version.

```http
POST /v1/transit/rewrap/:key_name
```

### Rewrap Request

```json
{
  "ciphertext": "egide:v1:AAAAAAAAAAAAA..."
}
```

### Rewrap Response

```json
{
  "data": {
    "ciphertext": "egide:v3:BBBBBBBBBBBBB..."
  }
}
```

Use rewrap after key rotation to update stored ciphertext.

## Batch Rewrap

Rewrap multiple items.

```http
POST /v1/transit/rewrap/:key_name/batch
```

### Batch Rewrap Request

```json
{
  "items": [
    {"ciphertext": "egide:v1:AAA..."},
    {"ciphertext": "egide:v2:BBB..."}
  ]
}
```

### Batch Rewrap Response

```json
{
  "data": {
    "results": [
      {"ciphertext": "egide:v3:CCC..."},
      {"ciphertext": "egide:v3:DDD..."}
    ]
  }
}
```

## Generate Datakey

Generate a data encryption key.

```http
POST /v1/transit/datakey/:key_name
```

### Generate Datakey Request

```json
{
  "type": "aes256",
  "context": "optional-context"
}
```

### Generate Datakey Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Key type (default: aes256) |
| `context` | string | Key derivation context (optional) |
| `bits` | integer | Key size in bits (default: 256) |

### Generate Datakey Response

```json
{
  "data": {
    "plaintext": "base64-encoded-key",
    "ciphertext": "egide:v1:encrypted-key"
  }
}
```

### Wrapped Datakey Only

For storage (no plaintext returned):

```json
{
  "type": "aes256",
  "wrapped_only": true
}
```

Response:

```json
{
  "data": {
    "ciphertext": "egide:v1:encrypted-key"
  }
}
```

## Envelope Encryption Pattern

1. **Generate datakey**:

```bash
curl -X POST \
  -H "Authorization: Bearer s.XXXX" \
  -d '{"type":"aes256"}' \
  https://egide.example.com/v1/transit/datakey/my-key
```

2. **Encrypt data locally** with `plaintext` key
3. **Store** encrypted data + `ciphertext` (encrypted key)
4. **Discard** `plaintext` key

To decrypt:

1. **Decrypt datakey**:

```bash
curl -X POST \
  -H "Authorization: Bearer s.XXXX" \
  -d '{"ciphertext":"egide:v1:..."}' \
  https://egide.example.com/v1/transit/decrypt/my-key
```

2. **Decrypt data locally** with the key

## Context (Key Derivation)

Use context for tenant isolation with a shared key:

```bash
# Tenant A
curl -X POST \
  -d '{"plaintext":"...", "context":"tenant-a"}' \
  https://egide.example.com/v1/transit/encrypt/shared-key

# Tenant B
curl -X POST \
  -d '{"plaintext":"...", "context":"tenant-b"}' \
  https://egide.example.com/v1/transit/encrypt/shared-key
```

Each context derives a unique key from the master key.

## Errors

| Code | Error | Description |
|------|-------|-------------|
| `400` | `invalid_ciphertext` | Malformed ciphertext |
| `400` | `invalid_plaintext` | Invalid base64 encoding |
| `404` | `key_not_found` | Key not found |
| `403` | `decryption_failed` | Decryption failed (wrong key or corrupted) |

## Next Steps

- [PKI API](pki.md) — Certificate management
- [Secrets API](secrets.md) — Secret storage
