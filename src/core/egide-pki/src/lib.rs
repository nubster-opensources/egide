//! # Egide PKI Engine
//!
//! Public Key Infrastructure for certificate management.
//!
//! ## Status
//!
//! This crate is a placeholder: only the error types exist today. The engine
//! itself is planned for the 0.4.0 release.
//!
//! ## Planned features
//!
//! - Root and Intermediate Certificate Authority
//! - TLS/mTLS certificate issuance
//! - Certificate templates
//! - Auto-renewal
//! - Certificate revocation (CRL)

#![forbid(unsafe_code)]

pub mod error;

pub use error::PkiError;
