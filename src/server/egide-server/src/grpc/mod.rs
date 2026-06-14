//! gRPC transport layer for Egide server.

pub mod auth;
pub mod secrets;
pub mod service_tokens;
pub mod status_map;
pub mod sys;
pub mod transit;

#[cfg(test)]
pub(crate) mod tests_support;

pub use secrets::SecretsGrpc;
pub use service_tokens::ServiceTokenGrpc;
pub use sys::SysGrpc;
pub use transit::TransitGrpc;
