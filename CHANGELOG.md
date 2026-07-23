# Changelog

All notable changes to Egide will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

> **Release note:** this batch includes a source break (`TransitError` is now
> `#[non_exhaustive]`) and an observable API surface change (`create_key`
> rejects `chacha20-poly1305`). It must ship as `0.2.0`, not a patch release.

### Added
- Storage: `egide_storage::pattern`, a public helper module exposing
  `escape_like_pattern` and `prefix_pattern`. Any backend or engine building a
  `LIKE` pattern from caller-supplied text must route it through these and
  state `ESCAPE '\'` in the query. SQLite defines no default escape character,
  so the clause is mandatory rather than decorative.

### Changed
- Transit: `create_key` refuses `chacha20-poly1305` at creation time. That
  type was accepted since 0.1.0 but never actually implemented: keys created
  with it were always encrypted under AES-256-GCM regardless. Accepting it
  produced a policy row and ciphertext labels no client could trust.
- `TransitError` is now `#[non_exhaustive]`. This is a source break for any
  consumer matching on it exhaustively (a wildcard arm is now required); it
  buys the room to add a variant in a future patch release instead of
  forcing a major version bump.
- Secrets: the `secret_versions` table gains a nullable `generation_salt`
  column. It is added automatically at startup by an idempotent
  `ALTER TABLE`; no operator action and no downtime are required.
- Secrets: versions written before this release carry no salt and are still
  derived under the previous `egide-secrets-v2:{path}:{version}` context. That
  context is retained on purpose and will remain as long as pre-upgrade rows
  can exist. Each row is self-describing: the presence or absence of a salt on
  the row alone selects the derivation.

### Fixed
- Transit: the ciphertext envelope now carries its own algorithm
  (`egide:v{n}:{base64}` for AES-256-GCM, `egide:v{n}:{algorithm}:{base64}`
  for anything else), and `decrypt` / `rewrap` check it against the engine's
  actual implemented algorithm, not against the key's declared `key_type`.
  Under 0.1.0, a key declared `chacha20-poly1305` was in fact always
  encrypted under AES-256-GCM, and `decrypt` performed no algorithm check at
  all; existing 0.1.0 ciphertexts under such a key remain readable exactly
  as before. What changes is `encrypt`: it now refuses to run on a key whose
  declared type is not the engine's implemented algorithm
  (`TransitError::KeyAlgorithmNotImplemented`), instead of silently
  encrypting under AES-256-GCM while the key still claims
  `chacha20-poly1305`.
- Storage: `put` and `delete` are now atomic. Both backends previously read the
  current version, then wrote the new row and its history entry in separate
  statements. Two concurrent writers could read the same version and produce
  duplicated history versions, losing one of the two writes from the audit
  trail. The version counter is now owned by the database itself
  (`INSERT ... ON CONFLICT DO UPDATE SET version = <existing row>.version + 1
  ... RETURNING version`) under the row lock, and the history entry is written in the same
  transaction. SQLite opens the transaction with `BEGIN IMMEDIATE` so the write
  lock is taken up front instead of being promoted mid-transaction.
- Storage: `list` escapes `%`, `_` and `\` in the caller-supplied prefix before
  building the `LIKE` pattern, on both the SQLite and PostgreSQL backends. A
  bound parameter stops SQL injection but never stopped `LIKE` from
  interpreting metacharacters inside the bound value: a prefix such as `%` or
  `a_` matched keys outside the requested prefix.
- Secrets: `list` had the same unescaped prefix, reachable through the HTTP and
  gRPC API. A prefix containing `%` or `_` returned secret paths outside the
  requested prefix. It now uses the shared escaping helper. This is a
  correctness fix on the prefix, not an access-control boundary: `list` applies
  no path scoping, and an empty prefix still lists every secret.

### Security
- Secrets: each secret generation now binds a fresh 32-byte random salt into
  the HKDF context (`egide-secrets-v3:{path}:{version}:{salt}`). HKDF is
  deterministic, so the previous context was fully determined by the path and
  the version number: purging a deleted secret reset its versions to 1, and the
  next write at that path re-derived the exact same encryption key as the
  purged data. Two unrelated secret versions therefore shared a key. The salt
  is a derivation nonce, not a secret, and is stored hex-encoded in clear on
  each row of `secret_versions`. All versions of one generation share that
  generation's salt; a purge followed by a new write at the same path draws a
  new one.

### Upgrade Notes
- A transit key declared `chacha20-poly1305` under 0.1.0 remains readable:
  its existing ciphertexts still decrypt. Any operation that produces a new
  ciphertext or a new key version on such a key now fails with
  `TransitError::KeyAlgorithmNotImplemented` (HTTP `409 Conflict`), including
  `encrypt`, `encrypt_with_version`, `generate_datakey`, `rotate_key`, and
  `rewrap` of a ciphertext that is not already at the key's latest version.
  `rewrap` of a ciphertext already at the latest version is a no-op and
  still succeeds, but this is not a migration path: the key stays declared
  under an algorithm this build does not implement, and running a rewrap
  sweep over it will report success without changing anything. Do not keep
  such a key in place: migrate by re-encrypting its data under a new key
  created with the default `aes256-gcm` type.
- Storage: no schema change and no migration. Both storage fixes are code-only.
- This release removes the version duplications caused by concurrent writers.
  It does not change one nominal behaviour: a `delete` removes the `kv_store`
  row, so a later write at the same path restarts at version 1 and adds another
  `(key, 1)` row to `kv_history`. A recreated key can therefore hold repeated
  versions in its history by design, with or without concurrency.
- Rows written by an earlier version under concurrent load may already carry
  concurrency-induced duplicates in `kv_history`. This release does not repair
  them. Auditing an installation that ran under concurrent writers is
  worthwhile.
- Case sensitivity of `LIKE` still differs between backends: SQLite is
  case-insensitive for ASCII, PostgreSQL is case-sensitive. Escaping is now
  identical across backends; matching semantics are not. Do not rely on a
  prefix listing being case-exact.
- Secrets: the upgrade is one-way for newly written secrets. Data written after
  the upgrade uses the v3 context and cannot be read by 0.1.0: rolling the
  binary back makes those secrets unreadable. Nothing is lost, since the salt
  stays stored on the row and upgrading again restores readability, but plan the
  rollback window accordingly.
- Secrets written before the upgrade remain readable in both directions.

## [0.1.0] - 2026-07-08

First public release. Egide provides a self-hosted Secrets Manager and Transit
encryption as a service, with a REST and gRPC server, native service tokens,
Shamir-based seal/unseal, and a SQLite storage backend. The KMS and PKI engines
are planned (see docs/explanation/roadmap.md); their crates ship as placeholders with error
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
