//! # Egide API
//!
//! REST and gRPC API layer for Egide.
//!
//! ## Endpoints
//!
//! - `/v1/secrets/*` - Secrets Engine API
//! - `/v1/transit/*` - Transit Engine API
//! - `/v1/kms/*` - KMS Engine API
//! - `/v1/pki/*` - PKI Engine API
//! - `/v1/sys/*` - System operations (seal, unseal, health)

#![forbid(unsafe_code)]
#![warn(missing_docs)]
