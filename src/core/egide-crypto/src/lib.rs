//! # Egide Crypto
//!
//! Core cryptographic primitives for Egide.
//!
//! This crate provides low-level cryptographic operations including:
//! - Symmetric encryption (AES-256-GCM)
//! - Key derivation (HKDF-SHA256)
//! - Secure random generation (OS CSPRNG)
//! - Memory-safe key types with automatic zeroization
//!
//! ## Security
//!
//! All sensitive key material is automatically zeroized when dropped.
//! Keys implement `Debug` with redacted output to prevent accidental logging.
//!
//! ## Example
//!
//! ```
//! use egide_crypto::{aead, keys::SymmetricKey};
//!
//! // Generate a key and encrypt some data
//! let key = SymmetricKey::generate();
//! let plaintext = b"secret message";
//!
//! let ciphertext = aead::encrypt(key.as_bytes(), plaintext, None).unwrap();
//! let decrypted = aead::decrypt(key.as_bytes(), &ciphertext, None).unwrap();
//!
//! assert_eq!(&*decrypted, plaintext);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod random;

pub use error::CryptoError;
pub use keys::{MasterKey, SymmetricKey};
