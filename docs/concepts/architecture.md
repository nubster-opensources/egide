# Architecture

This document describes the high-level architecture of Egide.

## Overview

Egide is built as a modular system with four core engines, each handling a specific aspect of secrets and key management:

```text
                    ┌─────────────────────────┐
                    │      Clients            │
                    │  (CLI, SDK, API calls)  │
                    └───────────┬─────────────┘
                                │
                    ┌───────────▼─────────────┐
                    │      REST / gRPC        │
                    │         API             │
                    └───────────┬─────────────┘
                                │
    ┌───────────────────────────┼───────────────────────────┐
    │                     EGIDE SERVER                       │
    │                                                        │
    │   ┌──────────┐  ┌──────────┐  ┌──────────┐            │
    │   │   Auth   │  │  Audit   │  │  Policy  │            │
    │   │  Engine  │  │   Log    │  │  Engine  │            │
    │   └──────────┘  └──────────┘  └──────────┘            │
    │                                                        │
    │   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────┐ │
    │   │ Secrets  │  │   KMS    │  │   PKI    │  │Transit│ │
    │   │ Engine   │  │  Engine  │  │  Engine  │  │Engine │ │
    │   └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬───┘ │
    │        └─────────────┴─────────────┴────────────┘     │
    │                          │                            │
    │                  ┌───────▼───────┐                    │
    │                  │  Crypto Core  │                    │
    │                  └───────────────┘                    │
    └──────────────────────────┬────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Storage Backend   │
                    │  (SQLite/PostgreSQL)│
                    └─────────────────────┘
```

## Core Components

### Engines

| Engine | Purpose |
|--------|---------|
| **Secrets Engine** | Key/Value store for sensitive data with versioning |
| **KMS Engine** | Cryptographic key lifecycle management |
| **PKI Engine** | Certificate Authority and certificate management |
| **Transit Engine** | Encryption as a Service |

### Supporting Components

| Component | Purpose |
|-----------|---------|
| **Auth Engine** | Authentication (Token, AppRole, OIDC, mTLS) |
| **Audit Log** | Immutable audit trail of all operations |
| **Policy Engine** | Access control and authorization |
| **Crypto Core** | Low-level cryptographic primitives |

## Security Model

### Seal/Unseal

Egide uses a seal/unseal mechanism to protect the master encryption key:

1. **Sealed State**: Egide starts sealed. All data is encrypted and inaccessible.
2. **Unseal Process**: Requires a threshold of unseal keys (Shamir's Secret Sharing).
3. **Unsealed State**: Master key is loaded in memory, data is accessible.

```text
                    ┌─────────────────┐
                    │  Master Key     │
                    │  (in memory)    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
        │  Key 1    │  │  Key 2    │  │  Key 3    │
        │ (share)   │  │ (share)   │  │ (share)   │
        └───────────┘  └───────────┘  └───────────┘
              │              │              │
              └──────────────┴──────────────┘
                             │
                    Shamir's Secret Sharing
                    (3 of 5 threshold)
```

### Encryption Layers

Data in Egide is protected by multiple encryption layers:

1. **Master Key**: Protects the encryption key hierarchy
2. **Data Encryption Key (DEK)**: Encrypts actual data
3. **Per-Tenant Keys**: Isolation in multi-tenant deployments

### Authentication Flow

```text
Client                    Egide                    Backend
  │                         │                         │
  │  1. Authenticate        │                         │
  │  (token/approle/oidc)   │                         │
  │ ────────────────────►   │                         │
  │                         │  2. Validate            │
  │                         │ ────────────────────►   │
  │                         │                         │
  │                         │  3. Return policies     │
  │                         │ ◄────────────────────   │
  │  4. Return token        │                         │
  │ ◄────────────────────   │                         │
  │                         │                         │
  │  5. Request + token     │                         │
  │ ────────────────────►   │                         │
  │                         │  6. Check policies      │
  │                         │  7. Execute operation   │
  │  8. Response            │                         │
  │ ◄────────────────────   │                         │
```

## Storage Architecture

Egide supports pluggable storage backends:

### SQLite (Default)

- Single-file database
- Ideal for development and standalone deployments
- No external dependencies

### PostgreSQL

- Production-grade reliability
- Supports high availability with replication
- Recommended for production

### Data Model

All data is stored encrypted:

```text
┌─────────────────────────────────────────────────┐
│                   Storage                        │
├─────────────────────────────────────────────────┤
│  secrets/                                        │
│  ├── myapp/database     → encrypted blob        │
│  ├── myapp/api-key      → encrypted blob        │
│  └── ...                                         │
│                                                  │
│  keys/                                           │
│  ├── encryption-key-1   → encrypted key blob    │
│  ├── signing-key-1      → encrypted key blob    │
│  └── ...                                         │
│                                                  │
│  pki/                                            │
│  ├── root-ca            → encrypted CA bundle   │
│  ├── certs/cert-001     → encrypted cert        │
│  └── ...                                         │
└─────────────────────────────────────────────────┘
```

## Multi-Tenancy

Egide supports multi-tenant deployments with cryptographic isolation:

- Each tenant has its own encryption key hierarchy
- Data is isolated at the storage level
- Policies control cross-tenant access (default: denied)

```text
┌─────────────────────────────────────────────────┐
│                  Egide Server                    │
├─────────────────────────────────────────────────┤
│  Tenant A                 Tenant B              │
│  ┌─────────────────┐     ┌─────────────────┐   │
│  │  Master Key A   │     │  Master Key B   │   │
│  │  Secrets A      │     │  Secrets B      │   │
│  │  Keys A         │     │  Keys B         │   │
│  └─────────────────┘     └─────────────────┘   │
└─────────────────────────────────────────────────┘
```

## High Availability

For production deployments, Egide can be deployed in HA mode:

### Single Node (Default)

- Simple deployment
- Suitable for development and small deployments
- No automatic failover

### Stateless + External Database

- Multiple Egide instances
- State stored in PostgreSQL
- Load balancer distributes requests
- Recommended for cloud deployments

```text
              ┌─────────────────┐
              │  Load Balancer  │
              └────────┬────────┘
                       │
         ┌─────────────┼─────────────┐
         │             │             │
    ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
    │ Egide 1 │   │ Egide 2 │   │ Egide 3 │
    └────┬────┘   └────┬────┘   └────┬────┘
         │             │             │
         └─────────────┼─────────────┘
                       │
              ┌────────▼────────┐
              │   PostgreSQL    │
              │   (Primary)     │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │   PostgreSQL    │
              │   (Replica)     │
              └─────────────────┘
```

## Next Steps

- [Secrets Engine](secrets-engine.md): Learn about secrets management
- [Security Model](../security/model.md): Deep dive into security
