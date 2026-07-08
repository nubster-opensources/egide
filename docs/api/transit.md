# Transit API

The Transit API provides Encryption as a Service endpoints. All endpoints require a bearer token (`Authorization: Bearer <token>`) and return `503` while the vault is sealed. Key management operations (create, delete, rotate) are root-only; data operations are open to any authenticated token.

Responses are flat JSON objects (no `data` envelope). Errors are RFC 9457 `application/problem+json` documents.

## Create Key

Create a named encryption key. Root-only.

```http
POST /v1/transit/keys
```

### Request

```json
{
  "name": "payments-key",
  "type": "aes256-gcm",
  "deletion_allowed": false
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | string | Key name (required) |
| `type` | string | `aes256-gcm` (default) or `chacha20-poly1305` |
| `deletion_allowed` | boolean | Whether the key may later be deleted (default: false) |

### Response

`201 Created`:

```json
{
  "name": "payments-key",
  "type": "aes256-gcm",
  "latest_version": 1
}
```

## List Keys

```http
GET /v1/transit/keys
```

### List Keys Response

```json
{
  "keys": ["payments-key", "pii-key"]
}
```

## Get Key

```http
GET /v1/transit/keys/:key_name
```

### Get Key Response

```json
{
  "name": "payments-key",
  "type": "aes256-gcm",
  "latest_version": 2,
  "min_encryption_version": 1,
  "min_decryption_version": 1,
  "supports_encryption": true,
  "supports_decryption": true,
  "deletion_allowed": false
}
```

## Delete Key

Root-only. The key must have been created with `deletion_allowed: true`, otherwise the call returns `403`.

```http
DELETE /v1/transit/keys/:key_name
```

Returns `204 No Content` on success.

## Rotate Key

Rotate a key to a new version. Root-only. Older versions remain available for decryption.

```http
POST /v1/transit/keys/:key_name/rotate
```

### Rotate Response

```json
{
  "version": 2
}
```

## Encrypt

Encrypt data without exposing the key.

```http
POST /v1/transit/encrypt/:key_name
```

### Encrypt Request

```json
{
  "plaintext": "base64-encoded-data"
}
```

### Encrypt Response

```json
{
  "ciphertext": "egide:v1:AAAAAAAAAAAAA..."
}
```

### Example

```bash
plaintext=$(echo -n "credit-card-number" | base64)
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d "{\"plaintext\":\"$plaintext\"}" \
  http://localhost:8200/v1/transit/encrypt/payments-key
```

## Decrypt

Decrypt data.

```http
POST /v1/transit/decrypt/:key_name
```

### Decrypt Request

```json
{
  "ciphertext": "egide:v1:AAAAAAAAAAAAA..."
}
```

### Decrypt Response

```json
{
  "plaintext": "base64-encoded-data"
}
```

## Rewrap

Re-encrypt ciphertext with the latest key version, without exposing plaintext. If the ciphertext is already at the latest version, it is returned unchanged.

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
  "ciphertext": "egide:v3:BBBBBBBBBBBBB..."
}
```

Use rewrap after key rotation to update stored ciphertext.

## Generate Datakey

Generate a data encryption key wrapped under a transit key. The request has no body.

```http
POST /v1/transit/datakey/:key_name
```

### Generate Datakey Response

```json
{
  "plaintext": "base64-encoded-key",
  "ciphertext": "egide:v1:encrypted-key"
}
```

## Envelope Encryption Pattern

1. **Generate datakey**:

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  http://localhost:8200/v1/transit/datakey/my-key
```

2. **Encrypt data locally** with the `plaintext` key
3. **Store** encrypted data + `ciphertext` (encrypted key)
4. **Discard** the `plaintext` key

To decrypt:

1. **Decrypt the datakey**:

```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ciphertext":"egide:v1:..."}' \
  http://localhost:8200/v1/transit/decrypt/my-key
```

2. **Decrypt data locally** with the recovered key

## Planned Features

> **Status: planned, not implemented yet.** The following features do not exist today:
>
> - Batch operations (`/v1/transit/encrypt/:key_name/batch` and equivalents): each call handles one value
> - Key-derivation `context` (convergent or per-tenant derived keys): use a separate named key per tenant instead
> - Datakey options (`type`, `bits`, `wrapped_only`): the datakey endpoint always returns a 256-bit key with both `plaintext` and `ciphertext`
> - Sign, verify, hash and HMAC endpoints: planned for 0.3.0

## Errors

Errors are RFC 9457 `application/problem+json`:

```json
{
  "type": "about:blank",
  "title": "Not Found",
  "status": 404,
  "detail": "not found"
}
```

| Code | Description |
|------|-------------|
| `400` | Invalid base64 plaintext, malformed ciphertext, version below minimum, decryption failed (anti-oracle: no distinction between wrong key and corrupted data) |
| `401` | Missing or invalid bearer token |
| `403` | Non-root caller on key management, or deletion not allowed for the key |
| `404` | Key or key version not found |
| `409` | Key with the same name already exists |
| `503` | Vault is sealed |

## Next Steps

- [Secrets API](secrets.md): Secret storage
- [System API](system.md): Administration
