//! # Egide Storage
//!
//! Storage abstraction layer for Egide backends.
//!
//! Provides traits and common types for implementing storage backends.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod pattern;

pub use backend::StorageBackend;
pub use error::StorageError;
pub use pattern::{escape_like_pattern, prefix_pattern, LIKE_ESCAPE_CHAR};
