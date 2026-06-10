//! # Egide KMS Engine
//!
//! Key Management Service for cryptographic key lifecycle management.
//!
//! ## Features
//!
//! - Key generation (AES-256, RSA, ECDSA, Ed25519)
//! - Encrypt/Decrypt operations
//! - Sign/Verify operations
//! - Key rotation with versioning
//! - Key policies and access control

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::KmsError;
