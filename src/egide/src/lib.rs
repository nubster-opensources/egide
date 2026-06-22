//! egide is a self-hosted KMS, Secrets Manager and Private CA written in Rust.
//!
//! This umbrella crate re-exports the egide building blocks behind feature
//! flags, so a single dependency gives access to the engines you need:
//!
//! ```toml
//! egide = { version = "0.1", features = ["kms", "transit"] }
//! ```
//!
//! Each engine is also available as a standalone crate (`egide-kms`,
//! `egide-transit`, ...). Enable `full` to pull every block in.

#[cfg(feature = "crypto")]
pub use egide_crypto as crypto;

#[cfg(feature = "storage")]
pub use egide_storage as storage;

#[cfg(feature = "storage-sqlite")]
pub use egide_storage_sqlite as storage_sqlite;

#[cfg(feature = "storage-postgres")]
pub use egide_storage_postgres as storage_postgres;

#[cfg(feature = "seal")]
pub use egide_seal as seal;

#[cfg(feature = "secrets")]
pub use egide_secrets as secrets;

#[cfg(feature = "kms")]
pub use egide_kms as kms;

#[cfg(feature = "pki")]
pub use egide_pki as pki;

#[cfg(feature = "transit")]
pub use egide_transit as transit;
