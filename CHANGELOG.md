# Changelog

All notable changes to Egide will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-15

First public release. Egide provides a self-hosted KMS, Secrets Manager and
Private CA, with a REST and gRPC server, native service tokens, Shamir-based
seal/unseal, and SQLite and PostgreSQL storage backends.

### Added
- Initial workspace structure and crate layout
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
