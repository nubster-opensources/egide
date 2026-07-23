# Egide Documentation

Welcome to the official documentation for **Egide**, a self-hosted secrets management server. Key management (KMS) and an internal certificate authority (PKI) are on the roadmap.

## What is Egide?

Egide (from Greek *aegis*, the shield of Athena) is a unified server for managing secrets, cryptographic keys and certificates. Built with security and data ownership in mind, Egide is designed around four engines. Two are implemented today, two are planned:

- **Secrets Engine** (implemented): secure storage for sensitive data with versioning and rotation
- **Transit Engine** (implemented): encryption as a service without exposing keys
- **KMS Engine** (planned 0.3.0): cryptographic key management with sign and verify operations
- **PKI Engine** (planned 0.4.0): internal certificate authority for TLS and mTLS certificates

See the [Roadmap](explanation/roadmap.md) for the release plan.

## Documentation Structure

### Getting Started

- [Installation](getting-started/installation.md): how to install Egide
- [Quick Start](getting-started/quick-start.md): get up and running in five minutes
- [Configuration](getting-started/configuration.md): configure Egide for your environment

### Concepts

- [Architecture](concepts/architecture.md): how Egide is designed
- [Secrets Engine](concepts/secrets-engine.md): key/value secrets storage
- [Transit Engine](concepts/transit-engine.md): encryption as a service
- [KMS Engine](concepts/kms-engine.md): key management and cryptographic operations (planned 0.3.0)
- [PKI Engine](concepts/pki-engine.md): certificate authority and certificate management (planned 0.4.0)
- [Authentication](concepts/authentication.md): authentication methods

### Guides

- [Docker Deployment](guides/docker.md): deploy with Docker and Docker Compose
- [Production Deployment](guides/production.md): best practices for production
- [High Availability](guides/high-availability.md): HA deployment patterns
- [Backup and Recovery](guides/backup.md): backup and disaster recovery

### API Reference

- [API Overview](api/overview.md): REST API conventions and authentication
- [Secrets API](api/secrets.md): `/v1/secrets/*` endpoints
- [Transit API](api/transit.md): `/v1/transit/*` endpoints
- [KMS API](api/kms.md): `/v1/kms/*` endpoints (planned 0.3.0, not served yet)
- [PKI API](api/pki.md): `/v1/pki/*` endpoints (planned 0.4.0, not served yet)
- [System API](api/system.md): `/v1/sys/*` endpoints

### Security

- [Security Model](security/model.md): how Egide protects your data
- [Security controls](security/compliance.md): data residency, audit trail, encryption, access control

### Policies

- [MSRV Policy](MSRV_POLICY.md): minimum supported Rust version guarantees
- [Semver Policy](SEMVER_POLICY.md): API stability and versioning conventions

### Decisions

- [Architecture Decision Records](adr/README.md): the significant, durable decisions behind Egide

## Quick Links

- [GitHub Repository](https://github.com/nubster-opensources/egide)
- [Report an Issue](https://github.com/nubster-opensources/egide/issues)
- [Roadmap](explanation/roadmap.md)

## License

Egide is dual licensed under the [MIT](https://github.com/nubster-opensources/egide/blob/main/LICENSE-MIT) and [Apache 2.0](https://github.com/nubster-opensources/egide/blob/main/LICENSE-APACHE) licenses, at your option.
