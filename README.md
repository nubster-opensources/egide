# Egide

[![CI](https://github.com/nubster-opensources/egide/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/nubster-opensources/egide/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.94-blue.svg)](./docs/MSRV_POLICY.md)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Status](https://img.shields.io/badge/status-alpha-yellow)](#status)
[![Made with Rust](https://img.shields.io/badge/made%20with-Rust-orange?logo=rust)](https://www.rust-lang.org/)

> A self-hosted secrets manager in Rust: encrypted key/value store and Transit
> encryption as a service behind a single REST and gRPC API, sealed at rest
> with Shamir secret sharing. Key management (KMS) and an internal certificate
> authority (PKI) are on the roadmap.

Egide is sponsored by [Nubster](https://nubster.com).

## Status

Alpha. The workspace is at `0.1.0`. The table below distinguishes what is implemented today from what is planned. See [ROADMAP.md](ROADMAP.md) for the detailed plan.

| Capability | Status |
| --- | --- |
| Crypto core (AES-256-GCM, HKDF, CSPRNG, zeroization) | 0.1.0 |
| Encrypted SQLite storage at rest | 0.1.0 |
| Secrets engine (versioned key/value, hierarchical paths, soft delete) | 0.1.0 |
| Transit engine (encrypt, decrypt, rewrap, datakey, key rotation) over the API | 0.1.0 |
| Seal/unseal with Shamir secret sharing | 0.1.0 |
| REST API and gRPC API | 0.1.0 |
| Native service tokens | 0.1.0 |
| PostgreSQL backend | 0.1.0 |
| CLI tool (operator and secrets commands) | 0.1.0 |
| AppRole auth | planned 0.2.0 |
| Append-only HMAC-signed audit log | planned 0.2.0 |
| KMS engine (named keys, sign, verify, asymmetric keys) | planned 0.3.0 |
| Transit sign, verify, hash and HMAC endpoints | planned 0.3.0 |
| PKI engine (internal root and intermediate CA, issuance, revocation) | planned 0.4.0 |
| Observability and high availability | planned 1.0.0 |

The `egide-kms` and `egide-pki` crates exist in the workspace as placeholders (error types only); their engines are not implemented yet.

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
```

The CLI currently covers operator and secrets commands. The Transit engine is
available through the REST and gRPC APIs:

```bash
# Encrypt data through the Transit engine (base64-encoded plaintext)
curl -s -X POST http://localhost:8200/v1/transit/encrypt/my-key \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"plaintext": "'"$(echo -n "sensitive data" | base64)"'"}'
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

- **One server, one sealed store.** Secrets and Transit share a single sealed store and one auth model today. KMS and PKI are planned on the same foundation, instead of four disjoint tools.
- **Keys never leave the server.** Applications call Transit to encrypt and decrypt. The key material stays inside Egide, sealed at rest. Sign and verify operations are planned with the KMS engine.
- **Sealed by default.** The master key is split with Shamir secret sharing. A fresh or restarted server is sealed and serves nothing until a quorum of operators unseals it.
- **Self-hostable.** Run it on your own infrastructure. An append-only, signed audit log is planned for 0.2.0.
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
| `egide-kms` | Placeholder for the KMS engine (planned 0.3.0): named keys, sign, verify |
| `egide-transit` | Transit engine: encryption as a service, rewrap, datakey generation |
| `egide-pki` | Placeholder for the PKI engine (planned 0.4.0): internal certificate authority |
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
