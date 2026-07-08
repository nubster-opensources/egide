# Changelog

All notable changes to Egide will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-08

First public release. Egide provides a self-hosted Secrets Manager and Transit
encryption as a service, with a REST and gRPC server, native service tokens,
Shamir-based seal/unseal, and a SQLite storage backend. The KMS and PKI engines
are planned (see ROADMAP.md); their crates ship as placeholders with error
types only.

### Added
- Initial workspace structure and crate layout
- Core cryptographic primitives (`egide-crypto`)
- Secrets Engine (`egide-secrets`): versioned key/value store with hierarchical paths and soft delete
- Transit Engine (`egide-transit`): encryption as a service, rewrap, datakey generation, key rotation
- Seal and unseal with Shamir secret sharing (`egide-seal`)
- Storage abstraction (`egide-storage`) with a SQLite backend; a PostgreSQL backend crate ships but is not yet selectable at server startup
- REST and gRPC API layer (`egide-api`)
- Native service tokens and root token authentication (`egide-auth`)
- CLI client (`egide-cli`) and server binary (`egide-server`)
- Placeholder crates for the planned KMS and PKI engines (`egide-kms`, `egide-pki`)

### Changed
- Upgraded the RustCrypto digest family to the 0.11 generation (hmac 0.13, sha2 0.11, hkdf 0.13)
- Upgraded rand to 0.10; key, nonce and token generation now surface CSPRNG failures as `CryptoError::RandomGenerationFailed` instead of aborting
- Upgraded sqlx to 0.9; dynamic SQL statements are explicitly marked with `AssertSqlSafe` after audit
- Raised the MSRV to Rust 1.94, required by sqlx 0.9

### Fixed
- CLI: the CLI now authenticates with `Authorization: Bearer` as documented;
  previously it sent a header the server ignored, so authenticated CLI
  commands failed with 401.

### Security
- AES-256-GCM for symmetric encryption, HKDF-SHA256 for key derivation, OS CSPRNG for randomness, memory zeroization for key material
- Shamir secret sharing for master key protection
- Secrets engine: the AES-256-GCM key is derived per secret version
  (HKDF domain `egide-secrets-v2:{path}:{version}`) and the AEAD associated
  data binds `path:version`, eliminating the GCM random-nonce birthday bound
  on rotated secrets and blocking cross-version ciphertext splicing
- Seal: malformed unseal shares (non-ASCII, odd-length or non-hex input) are
  rejected with `SealError::InvalidShare` instead of panicking on a
  misaligned UTF-8 boundary, which would abort the process in release builds
  and made unseal a denial-of-service vector
- Seal: dev mode requires the explicit `EGIDE_UNSAFE_DEV_MODE=1` environment
  marker and is categorically refused in release builds or when
  `EGIDE_ENV=production` is set, on both the initial activation and the
  restart-time auto-unseal of a dev-mode data directory
- Seal: the master key reconstruction HMAC is compared in constant time via
  `subtle::ConstantTimeEq` instead of a short-circuiting byte comparison
