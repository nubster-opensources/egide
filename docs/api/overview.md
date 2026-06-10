# API Overview

Egide provides a RESTful API for all operations.

## Base URL

```http
https://egide.example.com/v1
```

## Authentication

All API requests require authentication via Bearer token:

```bash
curl -H "Authorization: Bearer s.XXXX..." \
  https://egide.example.com/v1/secrets/myapp/database
```

Or using the `X-Egide-Token` header:

```bash
curl -H "X-Egide-Token: s.XXXX..." \
  https://egide.example.com/v1/secrets/myapp/database
```

## Content Type

All requests and responses use JSON:

```http
Content-Type: application/json
```

## HTTP Methods

| Method | Usage |
|--------|-------|
| `GET` | Read resources |
| `POST` | Create resources |
| `PUT` | Update resources (full replacement) |
| `PATCH` | Partial update |
| `DELETE` | Delete resources |
| `LIST` | List resources (GET with list semantics) |

## Response Format

### Success Response

```json
{
  "data": {
    "key": "value"
  },
  "metadata": {
    "version": 1,
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

### Error Response

```json
{
  "errors": [
    {
      "code": "not_found",
      "message": "Secret not found: myapp/database",
      "path": "/v1/secrets/myapp/database"
    }
  ]
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created |
| `204` | No Content (successful delete) |
| `400` | Bad Request (invalid input) |
| `401` | Unauthorized (missing or invalid token) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Not Found |
| `429` | Too Many Requests (rate limited) |
| `500` | Internal Server Error |
| `503` | Service Unavailable (sealed) |

## Pagination

List endpoints support pagination:

```bash
GET /v1/secrets?page=1&page_size=20
```

Response includes pagination metadata:

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 150,
    "total_pages": 8
  }
}
```

## Filtering

Some endpoints support filtering:

```bash
GET /v1/secrets?prefix=myapp/
```

## Versioning

API version is in the URL path: `/v1/...`

Breaking changes will increment the major version.

## Rate Limiting

Default rate limits:

| Endpoint | Limit |
|----------|-------|
| All endpoints | 1000 requests/minute |
| Auth endpoints | 100 requests/minute |

Rate limit headers:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1642248000
```

## API Endpoints

### System

| Endpoint | Description |
|----------|-------------|
| `GET /v1/sys/health` | Health check |
| `GET /v1/sys/seal-status` | Seal status |
| `POST /v1/sys/init` | Initialize Egide |
| `POST /v1/sys/unseal` | Unseal Egide |
| `POST /v1/sys/seal` | Seal Egide |

### Secrets

| Endpoint | Description |
|----------|-------------|
| `GET /v1/secrets/:path` | Read secret |
| `POST /v1/secrets/:path` | Create/update secret |
| `DELETE /v1/secrets/:path` | Delete secret |
| `GET /v1/secrets?list=true` | List secrets |

### KMS

| Endpoint | Description |
|----------|-------------|
| `GET /v1/kms/keys` | List keys |
| `POST /v1/kms/keys/:name` | Create key |
| `GET /v1/kms/keys/:name` | Get key info |
| `POST /v1/kms/keys/:name/rotate` | Rotate key |
| `POST /v1/kms/encrypt/:name` | Encrypt data |
| `POST /v1/kms/decrypt/:name` | Decrypt data |

### PKI

| Endpoint | Description |
|----------|-------------|
| `POST /v1/pki/root/generate` | Generate root CA |
| `POST /v1/pki/issue` | Issue certificate |
| `GET /v1/pki/cert/:serial` | Get certificate |
| `POST /v1/pki/revoke` | Revoke certificate |
| `GET /v1/pki/crl` | Get CRL |

### Transit

| Endpoint | Description |
|----------|-------------|
| `POST /v1/transit/encrypt/:name` | Encrypt |
| `POST /v1/transit/decrypt/:name` | Decrypt |
| `POST /v1/transit/rewrap/:name` | Rewrap |
| `POST /v1/transit/datakey/:name` | Generate datakey |

### Auth

| Endpoint | Description |
|----------|-------------|
| `POST /v1/auth/token/create` | Create token |
| `POST /v1/auth/token/revoke` | Revoke token |
| `POST /v1/auth/approle/login` | AppRole login |

## SDKs

Official SDKs are available for:

- Rust: `egide-sdk`
- .NET: `Nubster.Egide.SDK`
- TypeScript: `@nubster/egide`
- Python: `egide-sdk`
- Go: `github.com/nubster/egide-go`

## Next Steps

- [Secrets API](secrets.md) — Secrets endpoint reference
- [KMS API](kms.md) — KMS endpoint reference
- [Authentication](../concepts/authentication.md) — Authentication methods
