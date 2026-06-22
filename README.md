# Egide

[![CI](https://github.com/nubster-opensources/egide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nubster-opensources/egide/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](./docs/MSRV_POLICY.md)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status](https://img.shields.io/badge/status-alpha-yellow)](#status)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange?logo=rust)](https://www.rust-lang.org/)

> A self-hosted KMS and Secrets Manager in Rust: encrypted key/value store,
> key management, Transit encryption as a service, and an internal certificate
> authority, behind a single REST and gRPC API, sealed at rest with Shamir
> secret sharing.

Egide is sponsored by [Nubster](https://nubster.com).

## Status

Alpha. The workspace is at `0.1.0` and the features below shipped in that release. See [ROADMAP.md](ROADMAP.md) for the detailed plan.

| Capability | Version |
| --- | --- |
| Crypto core (AES-256-GCM, HKDF, CSPRNG, zeroization) | 0.1.0 |
| Encrypted SQLite storage at rest | 0.1.0 |
| Secrets engine (versioned key/value, hierarchical paths, soft delete) | 0.1.0 |
| KMS engine (named keys, rotation) and Transit (encrypt, decrypt, sign) | 0.1.0 |
| PKI engine (internal root and intermediate CA, issuance, revocation) | 0.1.0 |
| Seal/unseal with Shamir secret sharing | 0.1.0 |
| REST API and gRPC API | 0.1.0 |
| Native service tokens and AppRole auth | 0.1.0 |
| PostgreSQL backend | 0.1.0 |
| CLI tool | 0.1.0 |
| Append-only HMAC-signed audit log | planned 0.2.0 |
| Observability and high availability | planned 1.0.0 |

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

## Why Egide?

- **One server, four engines.** Secrets, KMS, Transit and PKI share a single sealed store, one auth model and one audit trail instead of four disjoint tools.
- **Keys never leave the server.** Applications call Transit to encrypt, decrypt and sign. The key material stays inside Egide, sealed at rest.
- **Sealed by default.** The master key is split with Shamir secret sharing. A fresh or restarted server is sealed and serves nothing until a quorum of operators unseals it.
- **GDPR-native.** Self-host anywhere, keep your data in the EU, and rely on an append-only audit log for compliance.
- **No lock-in.** Plain REST and gRPC over TLS, hierarchical paths, YAML policies. Nothing proprietary to adopt on the client side.

## What Egide is not

- **Not a general-purpose secret store for end users.** Egide is designed for infrastructure and application secrets, not password managers.
- **Not a managed service.** There is no hosted Egide; you run and operate it yourself.
- **Not a complete IAM solution.** It handles authentication tokens and YAML policies but does not replace a full identity provider.

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

## Documentation

- [Documentation index](docs/README.md)
- [Quick start](docs/getting-started/quick-start.md)
- [Architecture overview](docs/architecture/overview.md)
- [API reference](docs/api/overview.md)
- [Deployment guide](docs/deployment/overview.md)
- [Security model](docs/security/model.md)
- [MSRV policy](docs/MSRV_POLICY.md)
- [Semver policy](docs/SEMVER_POLICY.md)

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first for the workflow and conventions. For vulnerability reports, see [SECURITY.md](SECURITY.md).

Stability and versioning are documented in [`docs/SEMVER_POLICY.md`](./docs/SEMVER_POLICY.md) and [`docs/MSRV_POLICY.md`](./docs/MSRV_POLICY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual-licensed as above, without any additional terms or conditions.

Copyright (c) Nubster.
