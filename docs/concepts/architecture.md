# Architecture

This document describes the high-level architecture of Egide.

## Overview

Egide is built as a modular system with four core engines, each handling a specific aspect of secrets and key management. Two of the four engines (Secrets, Transit) are implemented today; KMS (planned 0.3.0) and PKI (planned 0.4.0) exist as placeholder crates. The diagram shows the target architecture:

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

| Engine | Status | Purpose |
|--------|--------|---------|
| **Secrets Engine** | Implemented | Key/Value store for sensitive data with versioning |
| **Transit Engine** | Implemented | Encryption as a Service |
| **KMS Engine** | Planned 0.3.0 | Cryptographic key lifecycle management |
| **PKI Engine** | Planned 0.4.0 | Certificate Authority and certificate management |

### Supporting Components

| Component | Status | Purpose |
|-----------|--------|---------|
| **Auth** | Implemented (root token + service tokens; AppRole planned 0.2.0, OIDC/mTLS planned) | Authentication |
| **Audit Log** | Planned 0.2.0 | Immutable audit trail of all operations |
| **Policy Engine** | Planned | Path-based access control (authorization today is root/non-root) |
| **Crypto Core** | Implemented | Low-level cryptographic primitives |

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

Today the flow is direct bearer-token validation: the client presents the root token or a service token on every request, Egide validates it against its stored hashes, and root-only operations additionally check the root context. The login-exchange flow below (credentials in, short-lived token out, policies attached) describes the target model once AppRole (planned 0.2.0) and the policy engine (planned) ship:

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

Egide uses a trait-based storage abstraction with pluggable backends:

### SQLite (the backend used today)

- One database file per internal engine under the data directory
- Ideal for development and standalone deployments
- No external dependencies

### PostgreSQL

> **Status: planned, not implemented yet.** The `egide-storage-postgres` crate exists in the workspace and is unit-tested, but `egide-server` does not yet expose a way to select it at startup (see [Configuration](../getting-started/configuration.md#storage-backend)). Once wired in, it targets production-grade reliability and high availability with replication.

### Data Model

All data is stored encrypted (the `keys/` and `pki/` areas below belong to the planned KMS and PKI engines):

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
- Data is isolated at the storage level (one SQLite file per tenant today)
- Cross-tenant policy controls are planned along with the policy engine

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

### Single Node (the deployment supported today)

- Simple deployment
- Suitable for development and small deployments
- No automatic failover

### Stateless + External Database

> **Status: planned, not implemented yet.** This mode requires the PostgreSQL backend to be selectable at server startup, which is not the case today (see above). Target shape:

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
