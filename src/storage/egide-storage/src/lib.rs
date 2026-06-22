//! # Egide Storage
//!
//! Storage abstraction layer for Egide backends.
//!
//! Provides traits and common types for implementing storage backends.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;

pub use backend::StorageBackend;
pub use error::StorageError;
