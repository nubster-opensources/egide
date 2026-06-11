# Architecture Overview

This document provides a comprehensive overview of Egide's architecture.

## System Architecture

```text
                              ┌─────────────────────────────────────┐
                              │            CLIENTS                   │
                              │  CLI │ SDK │ Web Console │ Services  │
                              └─────────────────┬───────────────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │     API Gateway       │
                                    │   REST + gRPC API     │
                                    └───────────┬───────────┘
                                                │
┌───────────────────────────────────────────────┼───────────────────────────────────────────────┐
│                                         EGIDE SERVER                                           │
│                                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              AUTHENTICATION LAYER                                        │  │
│  │                     Token │ AppRole │ OIDC │ mTLS │ Kubernetes                          │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              AUTHORIZATION LAYER                                         │  │
│  │                           Policy Engine │ RBAC │ ACLs                                   │  │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘  │
│                                                                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   SECRETS   │  │     KMS     │  │     PKI     │  │   TRANSIT   │  │       AUDIT         │  │
│  │   ENGINE    │  │   ENGINE    │  │   ENGINE    │  │   ENGINE    │  │       LOG           │  │
│  │             │  │             │  │             │  │             │  │                     │  │
│  │ • KV Store  │  │ • Keys      │  │ • CA        │  │ • Encrypt   │  │ • All operations    │  │
│  │ • Versions  │  │ • Encrypt   │  │ • Certs     │  │ • Decrypt   │  │ • Compliance        │  │
│  │ • TTL       │  │ • Sign      │  │ • CRL       │  │ • Rewrap    │  │ • Monitoring        │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────────────┘  │
│         │                │                │                │                                   │
│         └────────────────┴────────────────┴────────────────┘                                   │
│                                           │                                                    │
│                              ┌────────────▼────────────┐                                       │
│                              │      CRYPTO CORE        │                                       │
│                              │   AES-256-GCM │ RSA     │                                       │
│                              │   ECDSA │ Ed25519       │                                       │
│                              │   Shamir │ HKDF         │                                       │
│                              └────────────┬────────────┘                                       │
│                                           │                                                    │
└───────────────────────────────────────────┼────────────────────────────────────────────────────┘
                                            │
                               ┌────────────▼────────────┐
                               │    STORAGE BACKEND      │
                               │  PostgreSQL │ SQLite    │
                               └─────────────────────────┘
```

## Core Components

### 1. API Layer

The API layer handles all client communication through:

- **REST API** — Standard HTTP endpoints for all operations
- **gRPC API** — High-performance binary protocol for service-to-service communication

### 2. Authentication Layer

Supports multiple authentication methods:

| Method | Use Case |
|--------|----------|
| Token | Direct API access, scripts |
| AppRole | Machine-to-machine authentication |
| OIDC | Integration with identity providers |
| mTLS | Service mesh, zero-trust environments |
| Kubernetes | Native pod authentication |

### 3. Authorization Layer

Fine-grained access control through:

- **Policy Engine** — Path-based policies with capabilities
- **RBAC** — Role-based access control
- **ACLs** — Access control lists for fine-grained permissions

### 4. Engines

Each engine handles a specific domain:

| Engine | Responsibility |
|--------|----------------|
| Secrets | Key/Value storage with versioning |
| KMS | Cryptographic key lifecycle |
| PKI | Certificate Authority operations |
| Transit | Encryption as a Service |

### 5. Crypto Core

Low-level cryptographic operations:

- **Symmetric** — AES-256-GCM
- **Asymmetric** — RSA, ECDSA, Ed25519
- **Key Derivation** — HKDF, PBKDF2
- **Secret Sharing** — Shamir's Secret Sharing

### 6. Storage Backend

Pluggable storage backends:

- **PostgreSQL** — Production deployments
- **SQLite** — Development and standalone deployments

## Data Flow

### Secret Storage Flow

```text
Client                 Egide                    Storage
  │                      │                         │
  │  PUT /v1/secrets/x   │                         │
  │─────────────────────>│                         │
  │                      │                         │
  │                      │  Authenticate           │
  │                      │  Authorize              │
  │                      │  Encrypt (Crypto Core)  │
  │                      │                         │
  │                      │  Store encrypted data   │
  │                      │────────────────────────>│
  │                      │                         │
  │                      │<────────────────────────│
  │                      │                         │
  │<─────────────────────│                         │
  │      200 OK          │                         │
```

### Encryption Flow (Transit)

```text
Client                 Egide
  │                      │
  │  POST /v1/transit/   │
  │    encrypt/mykey     │
  │  { plaintext: ... }  │
  │─────────────────────>│
  │                      │
  │                      │  1. Authenticate
  │                      │  2. Authorize
  │                      │  3. Retrieve key
  │                      │  4. Encrypt with key
  │                      │
  │<─────────────────────│
  │  { ciphertext: ... } │
```

## Security Boundaries

### Trust Boundaries

1. **Client → API** — TLS encryption, authentication required
2. **API → Engines** — Internal, trusted
3. **Engines → Crypto** — Internal, trusted
4. **Crypto → Storage** — Data encrypted before storage

### Encryption Layers

| Layer | Protection |
|-------|------------|
| Transport | TLS 1.3 |
| Application | Per-tenant encryption |
| Storage | Master key encryption |

## Scalability

### Single Node

- Suitable for development and small deployments
- SQLite storage
- No external dependencies

### Stateless Cluster

- Multiple Egide instances
- Shared PostgreSQL database
- Load balancer for distribution
- Horizontal scaling

```text
                    ┌─────────────────┐
                    │  Load Balancer  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
    ┌────▼────┐         ┌────▼────┐         ┌────▼────┐
    │ Egide 1 │         │ Egide 2 │         │ Egide N │
    └────┬────┘         └────┬────┘         └────┬────┘
         │                   │                   │
         └───────────────────┼───────────────────┘
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

- [Secrets Engine Architecture](./secrets-engine.md)
- [KMS Engine Architecture](./kms-engine.md)
- [PKI Engine Architecture](./pki-engine.md)
- [Storage Architecture](./storage.md)
