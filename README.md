# Nubster Egide

  **Secure your secrets. Control your keys. Own your infrastructure.**

  Open-source secrets management, encryption, and PKI platform.  
  Sovereign and GDPR-native by design.

  [Features](#features) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

  ![License](https://img.shields.io/badge/license-BSL--1.1-blue)
  ![Rust](https://img.shields.io/badge/rust-1.79+-orange)
  ![Status](https://img.shields.io/badge/status-alpha-yellow)

  ---

## Why Egide?

  **Egide** (from Greek *aegis*, the shield of Athena) is a unified platform for managing secrets, cryptographic keys, and certificates. Built with security and data sovereignty in mind.

- **Centralized secrets** — Stop scattering credentials in .env files and config repos
- **Zero-knowledge encryption** — Your keys never leave your infrastructure
- **Self-hosted or cloud** — Deploy anywhere: on-premise, private cloud, or managed SaaS
- **Compliance-ready** — Designed for GDPR, SOC 2, ISO 27001, and SecNumCloud

## Features

### Secrets Engine

- **Key/Value store** with versioning and rollback
- **TTL & auto-expiration** for temporary credentials
- **Secret rotation** — manual and automated
- **Dynamic secrets** for databases and cloud providers

### KMS Engine (Key Management)

- **Encrypt / Decrypt** data without exposing keys
- **Sign / Verify** for digital signatures
- **Key rotation** with version management
- Support for **AES-256-GCM**, **RSA**, **ECDSA**, **Ed25519**

### PKI Engine (Certificates)

- **Internal Certificate Authority** — Root and Intermediate CAs
- **TLS/mTLS certificates** issuance on demand
- **Auto-renewal** before expiration
- Certificate templates and policies

### Transit Engine (Encryption as a Service)

- **Encryption as a Service** — applications never see the keys
- **Rewrap** — re-encrypt data with new key versions seamlessly
- **Datakey generation** for envelope encryption patterns

## Quick Start

### Using Docker

  ```bash
  docker run -d --name egide \
    -p 8200:8200 \
    -e EGIDE_DEV_MODE=true \
    nubster/egide:latest
  ```

### Using the CLI

  ```bash
  # Initialize and unseal
  egide operator init
  egide operator unseal

  # Store a secret
  egide secrets put myapp/database password=s3cr3t

  # Retrieve a secret
  egide secrets get myapp/database

  # Encrypt data (Transit)
  echo "sensitive data" | egide transit encrypt my-key
  ```

## SDKs

  Official SDKs for seamless integration:

  | Language   | Package                | Status       |
  |------------|------------------------|--------------|
  | Rust       | `egide-sdk`            | Coming soon  |
  | .NET       | `Nubster.Egide.SDK`    | Coming soon  |
  | TypeScript | `@nubster/egide`       | Coming soon  |
  | Python     | `egide-sdk`            | Coming soon  |
  | Go         | `github.com/nubster/egide-go` | Coming soon  |

## Deployment Options

  | Mode              | Description                                                        |
  |-------------------|--------------------------------------------------------------------|
  | **Egide Cloud**   | Managed SaaS at [egide.nubster.com](https://egide.nubster.com)     |
  | **Self-hosted**   | Deploy on your infrastructure (Docker, Kubernetes, bare metal)      |
  | **Nubster Platform** | Integrated with [Nubster Workspace](https://www.nubster.com)    |

## Compliance

  Egide is designed with compliance in mind:

  | Standard        | Support                                             |
  |-----------------|-----------------------------------------------------|
  | **GDPR**        | Data sovereignty, EU hosting, right to erasure      |
  | **SOC 2**       | Complete audit logging, access controls             |
  | **ISO 27001**   | Security controls framework                         |
  | **SecNumCloud** | French security certification ready                 |

## Architecture

  ``` text
                      ┌─────────────────────┐
                      │     REST / gRPC     │
                      │        API          │
                      └──────────┬──────────┘
                                 │
      ┌──────────────────────────┼──────────────────────────┐
      │                    EGIDE SERVER                      │
      │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
      │  │ Secrets │  │   KMS   │  │   PKI   │  │ Transit │ │
      │  │ Engine  │  │ Engine  │  │ Engine  │  │ Engine  │ │
      │  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘ │
      │       └────────────┴────────────┴────────────┘      │
      │                         │                           │
      │                  ┌──────┴──────┐                    │
      │                  │   Crypto    │                    │
      │                  │    Core     │                    │
      │                  └─────────────┘                    │
      └──────────────────────────┬──────────────────────────┘
                                 │
                      ┌──────────┴──────────┐
                      │   Storage Backend   │
                      │  (PostgreSQL/SQLite)│
                      └─────────────────────┘
  ```

## Documentation

- [Getting Started](docs/getting-started.md)
- [Architecture Overview](docs/architecture/overview.md)
- [API Reference](docs/api/README.md)
- [Deployment Guide](docs/deployment/README.md)
- [Security Model](docs/security/README.md)

## Contributing

  We welcome contributions! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a pull request.

## License

  Nubster Egide is licensed under the [Business Source License 1.1](LICENSE).

- **Permitted**: Internal use, development, testing, non-commercial use
- **Not Permitted**: Offering as a commercial managed service without a license
- **Change Date**: 4 years from release
- **Change License**: Apache License 2.0

## About Nubster

  Egide is part of the [Nubster](https://www.nubster.com) ecosystem — a GDPR-native, AI-powered development suite for European teams.

  ---

  Made with love in France
