# System API

The System API provides endpoints for Egide administration.

## Health Check

Check Egide health status.

```http
GET /v1/sys/health
```

### Response Codes

| Code | Status |
|------|--------|
| `200` | Unsealed, active |
| `429` | Unsealed, standby |
| `501` | Not initialized |
| `503` | Sealed |

### Response

```json
{
  "initialized": true,
  "sealed": false,
  "version": "0.1.0",
  "cluster_name": "egide-cluster"
}
```

## Seal Status

Get detailed seal status.

```http
GET /v1/sys/seal-status
```

### Seal Status Response

```json
{
  "sealed": true,
  "threshold": 3,
  "shares": 5,
  "progress": 1
}
```

## Initialize

Initialize a new Egide instance.

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

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `secret_shares` | integer | Number of key shares (default: 5) |
| `secret_threshold` | integer | Shares required to unseal (default: 3) |

### Initialize Response

```json
{
  "keys": [
    "key-share-1-base64",
    "key-share-2-base64",
    "key-share-3-base64",
    "key-share-4-base64",
    "key-share-5-base64"
  ],
  "root_token": "s.XXXXXXXXXXXX"
}
```

> **Important**: Save these keys securely. They cannot be retrieved again.

## Unseal

Provide an unseal key share.

```http
POST /v1/sys/unseal
```

### Unseal Request

```json
{
  "key": "key-share-base64"
}
```

### Unseal Response

```json
{
  "sealed": true,
  "threshold": 3,
  "shares": 5,
  "progress": 2
}
```

When threshold is reached:

```json
{
  "sealed": false,
  "threshold": 3,
  "shares": 5,
  "progress": 0
}
```

## Seal

Seal Egide (requires authentication).

```http
POST /v1/sys/seal
```

### Seal Response

```http
204 No Content
```

## Generate Root Token

Generate a new root token (requires unseal keys).

```http
POST /v1/sys/generate-root/init
```

### Generate Root Token Request

```json
{
  "otp": "base64-one-time-password"
}
```

### Generate Root Token Response

```json
{
  "nonce": "nonce-value",
  "progress": 0,
  "required": 3,
  "complete": false
}
```

Provide key shares:

```http
POST /v1/sys/generate-root/update
```

```json
{
  "key": "key-share-base64",
  "nonce": "nonce-value"
}
```

When complete:

```json
{
  "encoded_token": "encoded-root-token",
  "complete": true
}
```

## Audit Devices

### List Audit Devices

```http
GET /v1/sys/audit
```

### Enable Audit Device

```http
POST /v1/sys/audit/:name
```

```json
{
  "type": "file",
  "options": {
    "path": "/var/log/egide/audit.log"
  }
}
```

### Disable Audit Device

```http
DELETE /v1/sys/audit/:name
```

## Policies

### List Policies

```http
GET /v1/sys/policies
```

### Read Policy

```http
GET /v1/sys/policies/:name
```

### Create/Update Policy

```http
POST /v1/sys/policies/:name
```

```json
{
  "policy": "path \"secrets/*\" {\n  capabilities = [\"read\"]\n}"
}
```

### Delete Policy

```http
DELETE /v1/sys/policies/:name
```

## Auth Methods

### List Auth Methods

```http
GET /v1/sys/auth
```

### Enable Auth Method

```http
POST /v1/sys/auth/:path
```

```json
{
  "type": "approle"
}
```

### Disable Auth Method

```http
DELETE /v1/sys/auth/:path
```

## Leases

### List Leases

```http
GET /v1/sys/leases?prefix=:prefix
```

### Revoke Lease

```http
POST /v1/sys/leases/revoke
```

```json
{
  "lease_id": "lease-id"
}
```

### Revoke Prefix

```http
POST /v1/sys/leases/revoke-prefix/:prefix
```

## Metrics

Get Prometheus metrics.

```http
GET /metrics
```

### Metrics Response

```http
# HELP egide_requests_total Total number of requests
# TYPE egide_requests_total counter
egide_requests_total{method="GET",path="/v1/secrets"} 1234

# HELP egide_request_duration_seconds Request duration in seconds
# TYPE egide_request_duration_seconds histogram
egide_request_duration_seconds_bucket{le="0.01"} 100
...
```

## Configuration

### Reload Configuration

```http
POST /v1/sys/config/reload
```

### Get Configuration

```http
GET /v1/sys/config
```

## Errors

| Code | Error | Description |
|------|-------|-------------|
| `400` | `already_initialized` | Egide already initialized |
| `400` | `invalid_key` | Invalid unseal key |
| `503` | `sealed` | Egide is sealed |

## Next Steps

- [Authentication](../concepts/authentication.md) — Auth configuration
- [Production Deployment](../guides/production.md) — Production setup
