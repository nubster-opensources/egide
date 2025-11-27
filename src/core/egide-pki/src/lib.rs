//! # Egide PKI Engine
//!
//! Public Key Infrastructure for certificate management.
//!
//! ## Features
//!
//! - Root and Intermediate Certificate Authority
//! - TLS/mTLS certificate issuance
//! - Certificate templates
//! - Auto-renewal
//! - Certificate revocation (CRL)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::PkiError;
