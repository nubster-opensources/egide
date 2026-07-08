# System API

The System API provides endpoints for Egide administration. All request and response bodies below match the implemented handlers in `egide-server`.

## Health Check

Check Egide health status.

```http
GET /v1/sys/health
```

No authentication required. Always responds `200 OK`; the HTTP status code does not vary with seal or initialization state. Inspect the body fields instead.

### Response

```json
{
  "status": "ok",
  "version": "0.1.0",
  "initialized": true,
  "sealed": false,
  "uptime_secs": 42
}
```

## Status

Get the initialization and seal state.

```http
GET /v1/sys/status
```

No authentication required.

### Status Response

```json
{
  "version": "0.1.0",
  "initialized": true,
  "sealed": false
}
```

## Initialize

Initialize a new Egide instance. This is a bootstrap operation: no token is required (the generated shares and root token are the credentials).

```http
POST /v1/sys/init
```

### Request

```json
{
  "secret_shares": 5,
  "secret_threshold": 3
}
```

Both fields are optional and default to the values shown.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret_shares` | integer | Number of key shares (default: 5) |
| `secret_threshold` | integer | Shares required to unseal (default: 3) |

### Initialize Response

```json
{
  "root_token": "3e7c9a1f2b8d4560...",
  "keys": [
    "hex-share-1",
    "hex-share-2",
    "hex-share-3",
    "hex-share-4",
    "hex-share-5"
  ],
  "keys_base64": [
    "base64-share-1",
    "base64-share-2",
    "base64-share-3",
    "base64-share-4",
    "base64-share-5"
  ]
}
```

The root token is plain hex (no prefix) and is shown exactly once.

> **Important**: Save these keys securely. They cannot be retrieved again.

## Unseal

Provide one unseal key share. No token is required (the share itself is the credential).

```http
POST /v1/sys/unseal
```

### Unseal Request

```json
{
  "key": "hex-share"
}
```

The share is submitted in hex encoding (the `keys` array from init).

### Unseal Response

```json
{
  "sealed": true,
  "threshold": 3,
  "progress": 2
}
```

When the threshold is reached:

```json
{
  "sealed": false,
  "threshold": 3,
  "progress": 0
}
```

## Seal

Seal Egide, wiping the master key from memory. Requires the root token.

```http
POST /v1/sys/seal
Authorization: Bearer <root-token>
```

### Seal Response

```json
{
  "sealed": true
}
```

Returns `403` for non-root tokens and `400` if the vault is not currently unsealed.

## Errors

System endpoints return errors as a flat JSON object:

```json
{
  "error": "already initialized"
}
```

| Code | Description |
|------|-------------|
| `400` | Already initialized, invalid Shamir config, invalid or unknown unseal key, not unsealed |
| `401` | Missing or invalid bearer token (seal only; returned as RFC 9457 `application/problem+json`) |
| `403` | Non-root token on seal |
| `500` | Internal error |

## Planned Endpoints

> **Status: planned, not implemented yet.** The following administration surfaces do not exist today and return `404`:
>
> - `GET /v1/sys/seal-status` (use `GET /v1/sys/status` or `/v1/sys/health` instead)
> - `POST /v1/sys/generate-root/*` (root token regeneration; the root token is issued once at init)
> - `GET|POST|DELETE /v1/sys/audit*` (audit devices; audit log planned for 0.2.0)
> - `GET|POST|DELETE /v1/sys/policies*` (policy management; no policy engine exists yet)
> - `GET|POST /v1/sys/auth*` (pluggable auth methods; AppRole planned for 0.2.0)
> - `GET|POST /v1/sys/leases*` (lease management)
> - `GET /metrics` (Prometheus metrics)
> - `GET|POST /v1/sys/config*` (there is no configuration file; see [Configuration](../getting-started/configuration.md))

## Next Steps

- [Authentication](../concepts/authentication.md): Auth configuration
- [Production Deployment](../guides/production.md): Production setup
