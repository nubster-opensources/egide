# PKI API

The PKI API provides endpoints for certificate management.

## Generate Root CA

Initialize a root Certificate Authority.

```http
POST /v1/pki/root/generate
```

### Request

```json
{
  "common_name": "My Organization Root CA",
  "organization": "My Organization",
  "country": "FR",
  "ttl": "87600h",
  "key_type": "rsa4096"
}
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `common_name` | string | CA common name (required) |
| `organization` | string | Organization name |
| `country` | string | Country code (2 letters) |
| `ttl` | string | Certificate validity (default: 10 years) |
| `key_type` | string | Key type (default: rsa4096) |

### Response

```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "1234567890",
    "issuer": "CN=My Organization Root CA",
    "expiration": "2035-01-15T00:00:00Z"
  }
}
```

## Generate Intermediate CA

Create an intermediate CA signed by the root.

```http
POST /v1/pki/intermediate/generate
```

### Generate Intermediate CA Request

```json
{
  "common_name": "My Organization Intermediate CA",
  "organization": "My Organization",
  "ttl": "43800h"
}
```

### Generate Intermediate CA Response

```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "1234567891",
    "chain": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

## Issue Certificate

Issue an end-entity certificate.

```http
POST /v1/pki/issue
```

### Issue Certificate Request

```json
{
  "common_name": "api.example.com",
  "san": ["api.example.com", "api-internal.example.com"],
  "ip_san": ["10.0.0.5"],
  "ttl": "2160h",
  "template": "server"
}
```

### Issue Certificate Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `common_name` | string | Certificate CN (required) |
| `san` | array | DNS Subject Alternative Names |
| `ip_san` | array | IP Subject Alternative Names |
| `ttl` | string | Certificate validity (default: 90 days) |
| `template` | string | Certificate template |

### Templates

| Template | Key Usage | Extended Key Usage |
|----------|-----------|-------------------|
| `server` | Digital Signature, Key Encipherment | Server Auth |
| `client` | Digital Signature | Client Auth |
| `code-signing` | Digital Signature | Code Signing |

### Issue Certificate Response

```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "chain": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "1234567892",
    "expiration": "2025-04-15T00:00:00Z"
  }
}
```

## Get Certificate

Retrieve a certificate by serial number.

```http
GET /v1/pki/cert/:serial
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `chain` | boolean | Include certificate chain |

### Get Certificate Response

```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "1234567892",
    "common_name": "api.example.com",
    "san": ["api.example.com"],
    "issuer": "CN=My Organization Intermediate CA",
    "not_before": "2025-01-15T00:00:00Z",
    "not_after": "2025-04-15T00:00:00Z",
    "status": "valid"
  }
}
```

## List Certificates

List issued certificates.

```http
GET /v1/pki/certs
```

### List Certificates Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status (valid, expired, revoked) |
| `page` | integer | Page number |
| `page_size` | integer | Items per page |

### List Certificates Response

```json
{
  "data": {
    "certificates": [
      {
        "serial_number": "1234567892",
        "common_name": "api.example.com",
        "expiration": "2025-04-15T00:00:00Z",
        "status": "valid"
      }
    ]
  },
  "pagination": {
    "page": 1,
    "total": 50
  }
}
```

## Revoke Certificate

Revoke a certificate.

```http
POST /v1/pki/revoke
```

### Revoke Certificate Request

```json
{
  "serial_number": "1234567892",
  "reason": "key-compromise"
}
```

### Revocation Reasons

| Reason | Description |
|--------|-------------|
| `unspecified` | No reason given |
| `key-compromise` | Private key compromised |
| `ca-compromise` | CA compromised |
| `affiliation-changed` | Subject changed affiliation |
| `superseded` | Replaced by new certificate |
| `cessation-of-operation` | No longer needed |

### Revoke Certificate Response

```json
{
  "data": {
    "serial_number": "1234567892",
    "revoked_at": "2025-01-15T10:30:00Z",
    "reason": "key-compromise"
  }
}
```

## Get CRL

Get the Certificate Revocation List.

```http
GET /v1/pki/crl
```

### Get CRL Response

```http
-----BEGIN X509 CRL-----
...
-----END X509 CRL-----
```

Or as JSON:

```http
GET /v1/pki/crl?format=json
```

```json
{
  "data": {
    "crl": "-----BEGIN X509 CRL-----\n...",
    "next_update": "2025-01-22T00:00:00Z",
    "revoked": [
      {
        "serial_number": "1234567892",
        "revoked_at": "2025-01-15T10:30:00Z",
        "reason": "key-compromise"
      }
    ]
  }
}
```

## Renew Certificate

Renew an existing certificate.

```http
POST /v1/pki/renew/:serial
```

### Renew Certificate Response

```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "serial_number": "1234567893",
    "old_serial_number": "1234567892"
  }
}
```

## Get CA Certificate

Get the CA certificate chain.

```http
GET /v1/pki/ca
```

### Get CA Certificate Response

```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "chain": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

## Errors

| Code | Error | Description |
|------|-------|-------------|
| `400` | `invalid_cn` | Invalid common name |
| `400` | `invalid_san` | Invalid SAN entry |
| `404` | `cert_not_found` | Certificate not found |
| `409` | `already_revoked` | Certificate already revoked |
| `503` | `ca_not_initialized` | CA not initialized |

## Next Steps

- [System API](system.md) — System operations
- [Authentication](../concepts/authentication.md) — Auth methods
