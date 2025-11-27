# Egide Documentation

Welcome to the official documentation for **Nubster Egide**, an open-source secrets management, key management, and PKI platform.

## What is Egide?

Egide (from Greek *aegis*, the shield of Athena) is a unified platform for managing secrets, cryptographic keys, and certificates. Built with security and data sovereignty in mind, Egide provides:

- **Secrets Engine** — Secure storage for sensitive data with versioning and rotation
- **KMS Engine** — Cryptographic key management with encrypt/decrypt operations
- **PKI Engine** — Internal Certificate Authority for TLS/mTLS certificates
- **Transit Engine** — Encryption as a Service without exposing keys

## Documentation Structure

### Getting Started

- [Installation](getting-started/installation.md) — How to install Egide
- [Quick Start](getting-started/quick-start.md) — Get up and running in 5 minutes
- [Configuration](getting-started/configuration.md) — Configure Egide for your environment

### Concepts

- [Architecture](concepts/architecture.md) — How Egide is designed
- [Secrets Engine](concepts/secrets-engine.md) — Key/Value secrets storage
- [KMS Engine](concepts/kms-engine.md) — Key management and cryptographic operations
- [PKI Engine](concepts/pki-engine.md) — Certificate Authority and certificate management
- [Transit Engine](concepts/transit-engine.md) — Encryption as a Service
- [Authentication](concepts/authentication.md) — Authentication methods

### Guides

- [Docker Deployment](guides/docker.md) — Deploy with Docker and Docker Compose
- [Production Deployment](guides/production.md) — Best practices for production
- [High Availability](guides/high-availability.md) — HA deployment patterns
- [Backup & Recovery](guides/backup.md) — Backup and disaster recovery

### API Reference

- [API Overview](api/overview.md) — REST API conventions and authentication
- [Secrets API](api/secrets.md) — `/v1/secrets/*` endpoints
- [KMS API](api/kms.md) — `/v1/kms/*` endpoints
- [PKI API](api/pki.md) — `/v1/pki/*` endpoints
- [Transit API](api/transit.md) — `/v1/transit/*` endpoints
- [System API](api/system.md) — `/v1/sys/*` endpoints

### Security

- [Security Model](security/model.md) — How Egide protects your data
- [Compliance](security/compliance.md) — GDPR, SOC 2, ISO 27001 compliance

## Quick Links

- [GitHub Repository](https://github.com/nubster-opensources/egide)
- [Docker Hub](https://hub.docker.com/r/nubster/egide)
- [Report an Issue](https://github.com/nubster-opensources/egide/issues)

## License

Egide is licensed under the [Business Source License 1.1](https://github.com/nubster-opensources/egide/blob/main/LICENSE). After 4 years, each version becomes available under the Apache 2.0 license.
