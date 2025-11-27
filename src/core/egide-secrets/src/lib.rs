//! # Egide Secrets Engine
//!
//! Key/Value secrets store with versioning, TTL, and rotation support.
//!
//! ## Features
//!
//! - Versioned secrets with rollback capability
//! - TTL and auto-expiration
//! - Secret rotation (manual and automated)
//! - Metadata and custom attributes

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::SecretsError;
