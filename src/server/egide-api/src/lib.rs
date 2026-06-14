//! Transport-agnostic service layer for Egide.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod context;
pub use context::ServiceContext;

pub mod error;
pub use error::ServiceError;

pub mod secrets;

pub mod sys;

pub mod transit;

pub mod service_tokens;

/// Generated protobuf/gRPC types for the `egide.v1` package.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod proto {
    tonic::include_proto!("egide.v1");
    /// Reflection descriptor set.
    pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("egide_descriptor");
}

#[cfg(test)]
mod test_support;
