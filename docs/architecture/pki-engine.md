# PKI Engine Architecture

The PKI (Public Key Infrastructure) Engine provides an internal Certificate Authority for managing TLS/mTLS certificates.

## Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                         PKI ENGINE                               │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   CA Manager    │  │  Cert Issuer    │  │  Revocation     │  │
│  │                 │  │                 │  │                 │  │
│  │  • Root CA      │  │  • Templates    │  │  • CRL          │  │
│  │  • Intermediate │  │  • Issuance     │  │  • OCSP         │  │
│  │  • Chain mgmt   │  │  • Renewal      │  │  • Validation   │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                    │            │
│           └────────────────────┼────────────────────┘            │
│                                │                                 │
│                    ┌───────────▼───────────┐                     │
│                    │      Crypto Core      │                     │
│                    │    RSA │ ECDSA        │                     │
│                    └───────────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Certificate Authority Hierarchy

### Two-Tier Architecture

```text
                    ┌─────────────────────┐
                    │      Root CA        │
                    │  (Offline/Secure)   │
                    │   Valid: 20 years   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼────────┐ ┌─────▼─────┐ ┌───────▼───────┐
     │ Intermediate CA │ │Intermediate│ │ Intermediate  │
     │   (Servers)     │ │ (Clients)  │ │ (Code Sign)   │
     │  Valid: 5 years │ │ Valid: 5y  │ │  Valid: 5y    │
     └────────┬────────┘ └─────┬─────┘ └───────┬───────┘
              │                │               │
     ┌────────▼────────┐ ┌─────▼─────┐ ┌───────▼───────┐
     │  End-Entity     │ │End-Entity │ │  End-Entity   │
     │  Certificates   │ │Certificates│ │ Certificates │
     │  Valid: 1 year  │ │ Valid: 1y │ │  Valid: 1y    │
     └─────────────────┘ └───────────┘ └───────────────┘
```

## Data Model

### Certificate Authority

```rust
struct CertificateAuthority {
    id: Uuid,
    name: String,
    ca_type: CaType,  // Root, Intermediate
    parent_id: Option<Uuid>,
    certificate: X509Certificate,
    private_key: EncryptedPrivateKey,
    serial_number: u64,
    max_path_length: Option<u32>,
    valid_from: DateTime,
    valid_until: DateTime,
    created_at: DateTime,
}

enum CaType {
    Root,
    Intermediate,
}
```

### Certificate

```rust
struct Certificate {
    id: Uuid,
    ca_id: Uuid,
    serial_number: String,
    common_name: String,
    subject: Subject,
    san: Vec<SubjectAltName>,
    certificate: X509Certificate,
    valid_from: DateTime,
    valid_until: DateTime,
    revoked_at: Option<DateTime>,
    revocation_reason: Option<RevocationReason>,
}

struct Subject {
    common_name: String,
    organization: Option<String>,
    organizational_unit: Option<String>,
    country: Option<String>,
    state: Option<String>,
    locality: Option<String>,
}
```

## Certificate Templates

### Built-in Templates

| Template | Key Usage | Extended Key Usage |
|----------|-----------|-------------------|
| `server` | Digital Signature, Key Encipherment | TLS Server Auth |
| `client` | Digital Signature | TLS Client Auth |
| `code-signing` | Digital Signature | Code Signing |
| `email` | Digital Signature, Key Encipherment | Email Protection |

### Template Configuration

```yaml
templates:
  server:
    key_type: "ecdsa-p256"
    validity: "365d"
    key_usage:
      - digital_signature
      - key_encipherment
    extended_key_usage:
      - server_auth
    allow_any_name: false
    allowed_domains:
      - "*.example.com"
      - "*.internal"
    require_cn: true

  client:
    key_type: "ecdsa-p256"
    validity: "90d"
    key_usage:
      - digital_signature
    extended_key_usage:
      - client_auth
    allow_any_name: true
```

## Certificate Issuance

### Issuance Flow

```text
Client                     Egide PKI                    Storage
  │                            │                           │
  │  POST /v1/pki/issue        │                           │
  │  { cn, san, template }     │                           │
  │───────────────────────────>│                           │
  │                            │                           │
  │                            │  1. Validate request      │
  │                            │  2. Check permissions     │
  │                            │  3. Generate key pair     │
  │                            │  4. Create CSR            │
  │                            │  5. Sign with CA          │
  │                            │                           │
  │                            │  Store certificate        │
  │                            │──────────────────────────>│
  │                            │                           │
  │<───────────────────────────│                           │
  │  { cert, private_key,      │                           │
  │    ca_chain }              │                           │
```

### CSR-Based Issuance

```text
Client                     Egide PKI
  │                            │
  │  POST /v1/pki/sign         │
  │  { csr, template }         │
  │───────────────────────────>│
  │                            │
  │                            │  1. Parse CSR
  │                            │  2. Validate against template
  │                            │  3. Sign with CA
  │                            │
  │<───────────────────────────│
  │  { cert, ca_chain }        │
```

## Certificate Revocation

### Revocation Reasons

| Code | Reason |
|------|--------|
| 0 | Unspecified |
| 1 | Key Compromise |
| 2 | CA Compromise |
| 3 | Affiliation Changed |
| 4 | Superseded |
| 5 | Cessation of Operation |
| 6 | Certificate Hold |

### CRL (Certificate Revocation List)

```http
GET /v1/pki/crl

-----BEGIN X509 CRL-----
MIIBjTCB9wIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJGUjEPMA0GA1UE
...
-----END X509 CRL-----
```

### OCSP (Online Certificate Status Protocol)

```http
POST /v1/pki/ocsp

Request:  OCSP Request (DER encoded)
Response: OCSP Response (DER encoded)

Status: good | revoked | unknown
```

## Auto-Renewal

### Renewal Configuration

```yaml
renewal:
  enabled: true
  threshold: "30d"  # Renew 30 days before expiry
  grace_period: "7d"  # Grace period after expiry
```

### Renewal Process

```text
┌───────────────┐     ┌───────────────┐     ┌───────────────┐
│  Certificate  │     │   Renewal     │     │     New       │
│  Expiring     │────>│   Triggered   │────>│  Certificate  │
│  (< 30 days)  │     │               │     │   Issued      │
└───────────────┘     └───────────────┘     └───────────────┘
```

## Storage Schema

### PostgreSQL

```sql
CREATE TABLE pki_certificate_authorities (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    name TEXT NOT NULL,
    ca_type TEXT NOT NULL,
    parent_id UUID REFERENCES pki_certificate_authorities(id),
    certificate BYTEA NOT NULL,
    encrypted_private_key BYTEA NOT NULL,
    serial_number BIGINT NOT NULL DEFAULT 1,
    max_path_length INT,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(tenant_id, name)
);

CREATE TABLE pki_certificates (
    id UUID PRIMARY KEY,
    ca_id UUID REFERENCES pki_certificate_authorities(id),
    serial_number TEXT NOT NULL,
    common_name TEXT NOT NULL,
    subject JSONB NOT NULL,
    san JSONB,
    certificate BYTEA NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason INT,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE(ca_id, serial_number)
);

CREATE TABLE pki_templates (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    name TEXT NOT NULL,
    config JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_pki_certs_ca ON pki_certificates(ca_id);
CREATE INDEX idx_pki_certs_cn ON pki_certificates(common_name);
CREATE INDEX idx_pki_certs_expiry ON pki_certificates(valid_until);
CREATE INDEX idx_pki_certs_revoked ON pki_certificates(revoked_at) WHERE revoked_at IS NOT NULL;
```

## Security Considerations

### Private Key Protection

- CA private keys encrypted with tenant key
- Keys never exposed in API responses (except for issued end-entity certs)
- Hardware Security Module (HSM) support planned

### Certificate Validation

- Subject Alternative Name (SAN) validation
- Domain ownership verification (optional)
- Path length constraints enforced

## Next Steps

- [Transit Engine Architecture](./transit-engine.md)
- [Storage Architecture](./storage.md)
- [API Reference — PKI](../api/pki.md)
