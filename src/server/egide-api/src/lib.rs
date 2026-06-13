//! Transport-agnostic service layer for Egide.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod context;
pub use context::ServiceContext;

pub mod error;
pub use error::ServiceError;

pub mod sys;

#[cfg(test)]
mod test_support;
