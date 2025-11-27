# Secrets API

The Secrets API provides endpoints for managing secrets.

## Create/Update Secret

Create a new secret or update an existing one.

```http
POST /v1/secrets/:path
```

### Request

```json
{
  "data": {
    "username": "admin",
    "password": "supersecret"
  },
  "metadata": {
    "owner": "team-a",
    "environment": "production"
  },
  "ttl": "24h"
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `data` | object | Key-value pairs (required) |
| `metadata` | object | Custom metadata (optional) |
| `ttl` | string | Time to live (optional) |

### Response

```json
{
  "data": {
    "path": "myapp/database",
    "version": 1,
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

### Example

```bash
curl -X POST \
  -H "Authorization: Bearer s.XXXX" \
  -H "Content-Type: application/json" \
  -d '{"data":{"username":"admin","password":"secret"}}' \
  https://egide.example.com/v1/secrets/myapp/database
```

## Read Secret

Read a secret at the specified path.

```http
GET /v1/secrets/:path
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | integer | Specific version (optional) |

### Read Secret Response

```json
{
  "data": {
    "username": "admin",
    "password": "supersecret"
  },
  "metadata": {
    "path": "myapp/database",
    "version": 1,
    "created_at": "2025-01-15T10:30:00Z",
    "updated_at": "2025-01-15T10:30:00Z",
    "custom": {
      "owner": "team-a"
    }
  }
}
```

### Read Secret Example

```bash
# Get current version
curl -H "Authorization: Bearer s.XXXX" \
  https://egide.example.com/v1/secrets/myapp/database

# Get specific version
curl -H "Authorization: Bearer s.XXXX" \
  https://egide.example.com/v1/secrets/myapp/database?version=2
```

## List Secrets

List secrets at a path.

```http
GET /v1/secrets?list=true&prefix=:prefix
```

### List Secrets Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `list` | boolean | Enable list mode (required) |
| `prefix` | string | Path prefix (optional) |
| `page` | integer | Page number (default: 1) |
| `page_size` | integer | Items per page (default: 20) |

### List Secrets Response

```json
{
  "data": {
    "keys": [
      "myapp/",
      "shared/"
    ]
  },
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 2
  }
}
```

### List Secrets Example

```bash
# List all secrets
curl -H "Authorization: Bearer s.XXXX" \
  "https://egide.example.com/v1/secrets?list=true"

# List secrets under myapp/
curl -H "Authorization: Bearer s.XXXX" \
  "https://egide.example.com/v1/secrets?list=true&prefix=myapp/"
```

## Delete Secret

Delete a secret.

```http
DELETE /v1/secrets/:path
```

### Delete Secret Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `versions` | string | Comma-separated versions to delete |
| `permanent` | boolean | Permanently delete (default: false) |

### Delete Secret Response

```http
204 No Content
```

### Delete Secret Example

```bash
# Soft delete (can be recovered)
curl -X DELETE \
  -H "Authorization: Bearer s.XXXX" \
  https://egide.example.com/v1/secrets/myapp/database

# Delete specific versions
curl -X DELETE \
  -H "Authorization: Bearer s.XXXX" \
  "https://egide.example.com/v1/secrets/myapp/database?versions=1,2"

# Permanent delete
curl -X DELETE \
  -H "Authorization: Bearer s.XXXX" \
  "https://egide.example.com/v1/secrets/myapp/database?permanent=true"
```

## Recover Secret

Recover a soft-deleted secret.

```http
POST /v1/secrets/:path/recover
```

### Recover Secret Response

```json
{
  "data": {
    "path": "myapp/database",
    "recovered": true
  }
}
```

### Recover Secret Example

```bash
curl -X POST \
  -H "Authorization: Bearer s.XXXX" \
  https://egide.example.com/v1/secrets/myapp/database/recover
```

## Get Secret Metadata

Get metadata without the secret data.

```http
GET /v1/secrets/:path/metadata
```

### Get Secret Metadata Response

```json
{
  "data": {
    "path": "myapp/database",
    "current_version": 3,
    "versions": {
      "1": {
        "created_at": "2025-01-01T00:00:00Z",
        "deleted": false
      },
      "2": {
        "created_at": "2025-01-15T00:00:00Z",
        "deleted": true
      },
      "3": {
        "created_at": "2025-02-01T00:00:00Z",
        "deleted": false
      }
    },
    "custom": {
      "owner": "team-a"
    }
  }
}
```

## Update Metadata

Update secret metadata without changing the data.

```http
PATCH /v1/secrets/:path/metadata
```

### Update Metadata Request

```json
{
  "custom": {
    "owner": "team-b",
    "reviewed": true
  }
}
```

### Update Metadata Response

```json
{
  "data": {
    "path": "myapp/database",
    "updated": true
  }
}
```

## Errors

| Code | Error | Description |
|------|-------|-------------|
| `400` | `invalid_path` | Invalid secret path |
| `400` | `invalid_data` | Invalid secret data |
| `404` | `not_found` | Secret not found |
| `404` | `version_not_found` | Specified version not found |
| `410` | `expired` | Secret has expired |
| `403` | `permission_denied` | Insufficient permissions |

### Error Response

```json
{
  "errors": [
    {
      "code": "not_found",
      "message": "Secret not found: myapp/database"
    }
  ]
}
```

## Next Steps

- [KMS API](kms.md) — Key management API
- [Transit API](transit.md) — Encryption API
