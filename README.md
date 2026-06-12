# Egide

> Sovereign secrets management, key management and PKI server in Rust: encrypted key/value store, KMS, Transit encryption as a service and an internal certificate authority, behind a single REST and gRPC API.

[![CI](https://github.com/nubster-opensources/egide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nubster-opensources/egide/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.79-blue.svg)](Cargo.toml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status](https://img.shields.io/badge/status-alpha-yellow)](#status)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange?logo=rust)](https://www.rust-lang.org/)

Egide (from Greek *aegis*, the shield of Athena) is a secrets management server written in Rust. A single binary stores secrets, manages cryptographic keys, performs encryption on behalf of applications and runs an internal certificate authority, all behind one REST and gRPC API. Keys never leave the server, data is encrypted at rest with AES-256-GCM, and the server stays sealed until operators unseal it with Shamir key shares.

Egide is built for teams that want to own their secrets infrastructure end to end: self-hosted, GDPR-native, and designed from the start for SOC 2, ISO 27001 and SecNumCloud compliance.

Egide is sponsored by [Nubster](https://nubster.com).

## Why Egide?

- **One server, four engines.** Secrets, KMS, Transit and PKI share a single sealed store, one auth model and one audit trail instead of four disjoint tools.
- **Keys never leave the server.** Applications call Transit to encrypt, decrypt and sign. The key material stays inside Egide, sealed at rest.
- **Sealed by default.** The master key is split with Shamir secret sharing. A fresh or restarted server is sealed and serves nothing until a quorum of operators unseals it.
- **Sovereign and GDPR-native.** Self-host anywhere, keep your data in the EU, and rely on an append-only, HMAC-signed audit log for compliance.
- **No lock-in.** Plain REST and gRPC over TLS, hierarchical paths, YAML policies. Nothing proprietary to adopt on the client side.

## Status

Alpha. Nothing is released yet: the workspace is at `0.1.0-alpha` and the `v0.1.0` milestone is in development. The table below maps each capability to its target version. See [ROADMAP.md](ROADMAP.md) for the detailed plan.

| Capability | Target |
| --- | --- |
| Crypto core (AES-256-GCM, HKDF, CSPRNG, zeroization) | v0.1.0 |
| Encrypted SQLite storage at rest | v0.1.0 |
| Secrets engine (versioned key/value, hierarchical paths, soft delete) | v0.1.0 |
| Seal / unseal with Shamir secret sharing | v0.1.0 |
| REST API and CLI for secrets and operator commands | v0.1.0 |
| Tokens, YAML policies, AppRole and Userpass auth | v0.2.0 |
| Append-only HMAC-signed audit log | v0.2.0 |
| KMS engine (named keys, rotation) and Transit (encrypt, decrypt, sign) | v0.3.0 |
| PKI engine (internal root and intermediate CA, issuance, revocation) | v0.4.0 |
| PostgreSQL backend, gRPC API, observability and high availability | v1.0.0 |

## Workspace

| Crate | Role |
| --- | --- |
| `egide-crypto` | Cryptographic primitives: AES-256-GCM, HKDF-SHA256, OS CSPRNG, memory zeroization |
| `egide-seal` | Master key protection, Shamir secret sharing, seal and unseal |
| `egide-secrets` | Key/value secrets engine: versioning, hierarchical paths, soft delete |
| `egide-kms` | Key management engine: named keys, rotation, encrypt, decrypt, sign |
| `egide-transit` | Transit engine: encryption as a service, rewrap, datakey generation |
| `egide-pki` | PKI engine: internal certificate authority, issuance, renewal, revocation |
| `egide-storage` | Storage backend abstraction (async trait) |
| `egide-storage-sqlite` | SQLite storage backend |
| `egide-storage-postgres` | PostgreSQL storage backend |
| `egide-auth` | Authentication and policy framework |
| `egide-api` | REST and gRPC API layer |
| `egide-server` | Server daemon: configuration, wiring, bootstrap |
| `egide-cli` | `egide` command-line client |

## Quick start

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

# Encrypt data through the Transit engine
echo "sensitive data" | egide transit encrypt my-key
```

> Dev mode auto-unseals and is for local development only. Never run dev mode in production. See the [production checklist](docs/deployment/production-checklist.md).

### Service token provisioning

Egide issues native service tokens (`egst_<id>.<secret>`) for machine-to-machine authentication. All API calls require `Authorization: Bearer <token>`.

The provisioning flow is:

1. **Initialize** the server and collect the root token and Shamir shares.
2. **Unseal** the server by submitting at least `threshold` shares to `POST /v1/sys/unseal`.
3. **Create a service token** using the root token:

```bash
curl -s -X POST http://localhost:8200/v1/auth/service-tokens \
  -H "Authorization: Bearer <root-token>" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "my-service"}' \
  | jq .
# Returns: { "token_id": "...", "token": "egst_..." }
```

4. **Inject the token** into the consuming service as an environment variable or secret. The service then calls any `/v1/secrets/*` endpoint with `Authorization: Bearer egst_...`.

Service tokens can read and write secrets but cannot manage other tokens or perform operator actions such as sealing the server. Only the root token can create, list, or revoke service tokens.

## Architecture

```text
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
                    │ (SQLite/PostgreSQL) │
                    └─────────────────────┘
```

## Documentation

- [Documentation index](docs/README.md)
- [Quick start](docs/getting-started/quick-start.md)
- [Installation](docs/getting-started/installation.md)
- [Architecture overview](docs/architecture/overview.md)
- [API reference](docs/api/overview.md)
- [Deployment guide](docs/deployment/overview.md)
- [Security model](docs/security/model.md)

## Compliance

Egide is designed with compliance in mind from the start:

| Standard | Support |
| --- | --- |
| GDPR | Data sovereignty, EU hosting, right to erasure |
| SOC 2 | Append-only audit logging, access controls |
| ISO 27001 | Security controls framework |
| SecNumCloud | French security certification ready |

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first for the workflow and conventions. For vulnerability reports, see [SECURITY.md](SECURITY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Copyright © Nubster.
