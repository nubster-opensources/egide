//! # Egide Auth
//!
//! Authentication and authorization for Egide.
//!
//! ## Supported Methods
//!
//! - Token authentication
//! - AppRole (for services)
//! - OIDC (OpenID Connect)
//! - mTLS (mutual TLS)
//! - Nubster Identity integration

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::AuthError;
