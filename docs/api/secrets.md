# Secrets API

The Secrets API provides endpoints for managing secrets. All endpoints require a bearer token (`Authorization: Bearer <token>`) and return `503` while the vault is sealed.

Responses are flat JSON objects; errors are returned as `{"error": "..."}`.

## Create/Update Secret

Create a new secret or update an existing one (writes a new version).

```http
PUT /v1/secrets/:path
```

### Request

```json
{
  "data": {
    "username": "admin",
    "password": "supersecret"
  },
  "cas": 1
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | object | String key-value pairs (required) |
| `cas` | integer | Check-and-set guard: only write if the current version equals this value; omit for an unconditional write (optional) |

### Response

```json
{
  "version": 2
}
```

A `cas` mismatch returns `409 Conflict`.

### Example

```bash
curl -X PUT \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"admin","password":"secret"}}' \
  http://localhost:8200/v1/secrets/myapp/database
```

## Read Secret

Read the current version of a secret at the specified path.

```http
GET /v1/secrets/:path
```

### Read Secret Response

```json
{
  "data": {
    "username": "admin",
    "password": "supersecret"
  },
  "metadata": {
    "version": 1,
    "created_at": 1736935800,
    "deleted": false
  }
}
```

`created_at` is a unix timestamp in seconds.

### Read Secret Example

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8200/v1/secrets/myapp/database
```

> Reading a specific older version over the REST API (`?version=N`) is planned, not implemented yet; `GET` always returns the current version.

## List Secrets

List all secret paths.

```http
GET /v1/secrets
```

### List Secrets Response

```json
{
  "keys": [
    "myapp/database",
    "myapp/api-key",
    "shared/smtp"
  ]
}
```

### List Secrets Example

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8200/v1/secrets
```

> Prefix filtering and pagination query parameters are planned, not implemented yet; the endpoint returns all paths.

## Delete Secret

Soft-delete a secret (the record is marked deleted, versions are retained by the engine).

```http
DELETE /v1/secrets/:path
```

### Delete Secret Response

```http
204 No Content
```

### Delete Secret Example

```bash
curl -X DELETE \
  -H "Authorization: Bearer <token>" \
  http://localhost:8200/v1/secrets/myapp/database
```

> Version-targeted deletion (`?versions=1,2`), permanent deletion (`?permanent=true`), a recover endpoint, and dedicated metadata endpoints (`GET`/`PATCH /v1/secrets/:path/metadata`) are planned, not implemented yet. TTL and custom metadata on secrets are not implemented either.

## Errors

```json
{
  "error": "not found"
}
```

| Code | Description |
|------|-------------|
| `400` | Invalid path or data |
| `401` | Missing or invalid bearer token (returned as RFC 9457 `application/problem+json`) |
| `404` | Secret not found |
| `409` | Check-and-set (`cas`) version mismatch |
| `503` | Vault is sealed |

## Next Steps

- [Transit API](transit.md): Encryption API
- [System API](system.md): Administration
