//! # Egide Crypto
//!
//! Core cryptographic primitives for Nubster Egide.
//!
//! This crate provides low-level cryptographic operations including:
//! - Symmetric encryption (AES-256-GCM)
//! - Asymmetric encryption (RSA, ECDSA)
//! - Digital signatures (Ed25519)
//! - Key derivation (HKDF, PBKDF2)
//! - Secure random generation

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

pub use error::CryptoError;
