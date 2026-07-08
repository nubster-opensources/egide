# API Overview

Egide provides a RESTful API for all operations (a gRPC API with the same surface is served on the gRPC bind address).

## Base URL

```http
http://<host>:8200/v1
```

The server itself speaks plain HTTP; terminate TLS at a reverse proxy or load balancer in front of Egide (server-side TLS is planned, not implemented yet; see [Configuration](../getting-started/configuration.md#tls)).

## Authentication

All API requests (except health, status, init and unseal) require a bearer token:

```bash
curl -H "Authorization: Bearer <token>" \
  http://localhost:8200/v1/secrets/myapp/database
```

The token is either the root token (plain hex, issued once at init) or a service token (`egst_<id>.<secret>`). No other header form is accepted. See [Authentication](../concepts/authentication.md).

## Content Type

All requests and responses use JSON:

```http
Content-Type: application/json
```

## HTTP Methods

| Method | Usage |
|--------|-------|
| `GET` | Read resources and list collections |
| `POST` | Create resources and trigger operations |
| `PUT` | Create or update a secret |
| `DELETE` | Delete resources |

## Response Format

Responses are flat JSON objects specific to each endpoint (there is no generic `data`/`metadata` envelope). For example, a secret read returns:

```json
{
  "data": {
    "key": "value"
  },
  "metadata": {
    "version": 1,
    "created_at": 1736935800,
    "deleted": false
  }
}
```

while a transit encrypt returns simply `{"ciphertext": "egide:v1:..."}`.

### Error Responses

Two error formats exist today, depending on the endpoint family:

System (`/v1/sys/*`) and secrets endpoints return a flat error object:

```json
{
  "error": "not found"
}
```

Authentication failures, service-token endpoints, and transit endpoints return RFC 9457 `application/problem+json`:

```json
{
  "type": "about:blank",
  "title": "Not Found",
  "status": 404,
  "detail": "not found"
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created (service token, transit key) |
| `204` | No Content (successful delete) |
| `400` | Bad Request (invalid input, decryption failed) |
| `401` | Unauthorized (missing or invalid token) |
| `403` | Forbidden (root-only operation, deletion not allowed) |
| `404` | Not Found |
| `409` | Conflict (duplicate key, check-and-set mismatch) |
| `500` | Internal Server Error |
| `503` | Service Unavailable (sealed) |

## Versioning

API version is in the URL path: `/v1/...`

Breaking changes will increment the major version.

## Pagination, Filtering and Rate Limiting

> **Status: planned, not implemented yet.** List endpoints return complete result sets; there are no `page`/`page_size`/`prefix` query parameters and no rate limiting or `X-RateLimit-*` headers today.

## API Endpoints

### System

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /v1/sys/health` | none | Health check (always 200; seal state in the body) |
| `GET /v1/sys/status` | none | Initialization and seal state |
| `POST /v1/sys/init` | none (bootstrap) | Initialize Egide |
| `POST /v1/sys/unseal` | none (share is the credential) | Submit one unseal share |
| `POST /v1/sys/seal` | root | Seal Egide |

### Secrets

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /v1/secrets/:path` | bearer | Read secret |
| `PUT /v1/secrets/:path` | bearer | Create/update secret (optional `cas` guard) |
| `DELETE /v1/secrets/:path` | bearer | Soft-delete secret |
| `GET /v1/secrets` | bearer | List all secret paths |

### Transit

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /v1/transit/keys` | root | Create key |
| `GET /v1/transit/keys` | bearer | List keys |
| `GET /v1/transit/keys/:name` | bearer | Get key info |
| `DELETE /v1/transit/keys/:name` | root | Delete key (requires `deletion_allowed`) |
| `POST /v1/transit/keys/:name/rotate` | root | Rotate key |
| `POST /v1/transit/encrypt/:name` | bearer | Encrypt |
| `POST /v1/transit/decrypt/:name` | bearer | Decrypt |
| `POST /v1/transit/rewrap/:name` | bearer | Rewrap |
| `POST /v1/transit/datakey/:name` | bearer | Generate datakey |

### Auth (Service Tokens)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /v1/auth/service-tokens` | root | Create service token |
| `GET /v1/auth/service-tokens` | root | List service tokens |
| `DELETE /v1/auth/service-tokens/:token_id` | root | Revoke service token |

### KMS

> **Status: planned for 0.3.0, not implemented yet.** No `/v1/kms/*` endpoint is served today. See [KMS API](kms.md) for the target design.

### PKI

> **Status: planned for 0.4.0, not implemented yet.** No `/v1/pki/*` endpoint is served today. See [PKI API](pki.md) for the target design.

## SDKs

Official SDKs are planned for:

- Rust: `egide-sdk`
- .NET: `Nubster.Egide.SDK`
- TypeScript: `@nubster/egide`
- Python: `egide-sdk`
- Go: `github.com/nubster/egide-go`

## Next Steps

- [Secrets API](secrets.md): Secrets endpoint reference
- [Transit API](transit.md): Transit endpoint reference
- [Authentication](../concepts/authentication.md): Authentication methods
