# Changelog

All notable changes to Egide will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Secrets engine: the AES-256-GCM key is now derived per secret version
  (HKDF domain `egide-secrets-v2:{path}:{version}`) and the AEAD associated
  data binds `path:version`, eliminating the GCM random-nonce birthday bound
  on rotated secrets and blocking cross-version ciphertext splicing.
  Breaking at-rest format change: data written by earlier development builds
  is no longer decryptable.

### Changed
- Upgraded the RustCrypto digest family to the 0.11 generation (hmac 0.13, sha2 0.11, hkdf 0.13)
- Upgraded rand to 0.10; key, nonce and token generation now surface CSPRNG failures as `CryptoError::RandomGenerationFailed` instead of aborting
- Upgraded sqlx to 0.9; dynamic SQL statements are explicitly marked with `AssertSqlSafe` after audit
- Raised the MSRV from Rust 1.88 to Rust 1.94, required by sqlx 0.9

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
