//! # Egide KMS Engine
//!
//! Key Management Service for cryptographic key lifecycle management.
//!
//! ## Status
//!
//! This crate is a placeholder: only the error types exist today. The engine
//! itself is planned for the 0.3.0 release.
//!
//! ## Planned features
//!
//! - Key generation (AES-256, RSA, ECDSA, Ed25519)
//! - Encrypt/Decrypt operations
//! - Sign/Verify operations
//! - Key rotation with versioning
//! - Key policies and access control

#![forbid(unsafe_code)]

pub mod error;

pub use error::KmsError;
