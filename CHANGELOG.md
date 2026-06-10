# Changelog

All notable changes to Nubster Egide will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure
- Core cryptographic primitives (`egide-crypto`)
- Secrets Engine (`egide-secrets`)
- KMS Engine (`egide-kms`)
- PKI Engine (`egide-pki`)
- Transit Engine (`egide-transit`)
- Storage abstraction with PostgreSQL and SQLite backends
- REST API layer (`egide-api`)
- Authentication framework (`egide-auth`)
- CLI tool (`egide-cli`)
- Server binary (`egide-server`)

### Security
- AES-256-GCM for symmetric encryption
- RSA, ECDSA, Ed25519 for asymmetric operations
- Shamir's Secret Sharing for master key protection
