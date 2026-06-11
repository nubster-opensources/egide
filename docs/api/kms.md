# KMS API

The KMS API provides endpoints for key management and cryptographic operations.

## Create Key

Create a new encryption key.

```http
POST /v1/kms/keys/:name
```

### Request

```json
{
  "type": "aes256",
  "exportable": false,
  "allow_deletion": true
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Key type (required) |
| `exportable` | boolean | Allow key export (default: false) |
| `allow_deletion` | boolean | Allow key deletion (default: true) |

### Key Types

| Type | Description |
|------|-------------|
| `aes256` | AES-256-GCM (symmetric) |
| `rsa2048` | RSA 2048-bit |
| `rsa4096` | RSA 4096-bit |
| `ecdsa-p256` | ECDSA P-256 |
| `ecdsa-p384` | ECDSA P-384 |
| `ed25519` | Ed25519 |

### Create Key Response

```json
{
  "data": {
    "name": "my-key",
    "type": "aes256",
    "version": 1,
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

## List Keys

List all keys.

```http
GET /v1/kms/keys
```

### List Keys Response

```json
{
  "data": {
    "keys": [
      {
        "name": "encryption-key",
        "type": "aes256",
        "version": 2
      },
      {
        "name": "signing-key",
        "type": "rsa4096",
        "version": 1
      }
    ]
  }
}
```

## Get Key Info

Get information about a key.

```http
GET /v1/kms/keys/:name
```

### Get Key Response

```json
{
  "data": {
    "name": "my-key",
    "type": "aes256",
    "current_version": 2,
    "versions": [
      {
        "version": 1,
        "created_at": "2025-01-01T00:00:00Z",
        "status": "decrypt-only"
      },
      {
        "version": 2,
        "created_at": "2025-02-01T00:00:00Z",
        "status": "active"
      }
    ],
    "exportable": false,
    "allow_deletion": true,
    "created_at": "2025-01-01T00:00:00Z"
  }
}
```

## Rotate Key

Create a new version of the key.

```http
POST /v1/kms/keys/:name/rotate
```

### Rotate Key Response

```json
{
  "data": {
    "name": "my-key",
    "new_version": 3
  }
}
```

## Delete Key

Delete a key.

```http
DELETE /v1/kms/keys/:name
```

### Response

```http
204 No Content
```

## Encrypt

Encrypt data using a key.

```http
POST /v1/kms/encrypt/:name
```

### Encrypt Request

```json
{
  "plaintext": "base64-encoded-data",
  "context": "optional-aad"
}
```

### Encrypt Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | string | Base64-encoded data (required) |
| `context` | string | Additional authenticated data (optional) |

### Encrypt Response

```json
{
  "data": {
    "ciphertext": "egide:v1:base64-encoded-ciphertext",
    "key_version": 2
  }
}
```

### Example

```bash
# Encrypt
plaintext=$(echo -n "secret data" | base64)
curl -X POST \
  -H "Authorization: Bearer s.XXXX" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$plaintext\"}" \
  https://egide.example.com/v1/kms/encrypt/my-key
```

## Decrypt

Decrypt data using a key.

```http
POST /v1/kms/decrypt/:name
```

### Decrypt Request

```json
{
  "ciphertext": "egide:v1:base64-encoded-ciphertext",
  "context": "optional-aad"
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

## Sign

Sign data using a key.

```http
POST /v1/kms/sign/:name
```

### Sign Request

```json
{
  "data": "base64-encoded-data",
  "algorithm": "sha256"
}
```

### Sign Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | string | Base64-encoded data (required) |
| `algorithm` | string | Hash algorithm (default: sha256) |

### Sign Response

```json
{
  "data": {
    "signature": "base64-encoded-signature",
    "key_version": 1
  }
}
```

## Verify

Verify a signature.

```http
POST /v1/kms/verify/:name
```

### Verify Request

```json
{
  "data": "base64-encoded-data",
  "signature": "base64-encoded-signature",
  "algorithm": "sha256"
}
```

### Verify Response

```json
{
  "data": {
    "valid": true
  }
}
```

## Export Key (if enabled)

Export a key (only if created with `exportable: true`).

```http
GET /v1/kms/keys/:name/export
```

### Export Key Response

```json
{
  "data": {
    "name": "my-key",
    "type": "aes256",
    "version": 1,
    "key": "base64-encoded-key"
  }
}
```

## Errors

| Code | Error | Description |
|------|-------|-------------|
| `400` | `invalid_key_type` | Unsupported key type |
| `400` | `operation_not_allowed` | Operation not supported for key type |
| `404` | `key_not_found` | Key not found |
| `403` | `export_disabled` | Key is not exportable |
| `403` | `deletion_disabled` | Key deletion is disabled |

## Next Steps

- [Transit API](transit.md) — Encryption as a Service
- [PKI API](pki.md) — Certificate management
