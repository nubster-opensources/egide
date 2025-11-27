//! # Egide Transit Engine
//!
//! Encryption as a Service - applications encrypt/decrypt without seeing keys.
//!
//! ## Features
//!
//! - Encrypt/Decrypt data via API
//! - Rewrap (re-encrypt with new key version)
//! - Datakey generation for envelope encryption
//! - Batch operations

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::TransitError;
