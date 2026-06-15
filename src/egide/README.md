# egide

Sovereign KMS, Secrets Manager and Private CA written in Rust.

This is the umbrella crate. It re-exports the Egide building blocks behind
feature flags:

    egide = { version = "0.1", features = ["kms", "transit"] }

Available features: `crypto`, `storage`, `storage-sqlite`, `storage-postgres`,
`seal`, `secrets`, `kms`, `pki`, `transit`, and `full`.

Each block is also published as a standalone crate (`egide-kms`,
`egide-transit`, ...).

Licensed under MIT OR Apache-2.0.
