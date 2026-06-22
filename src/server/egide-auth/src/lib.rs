//! # Egide Auth
//!
//! Authentication and authorization for Egide.
//!
//! ## Supported Backends
//!
//! - **Root Token**: Single-token auth (dev mode, standalone).
//! - **Service Token**: Native machine-to-machine tokens issued by Egide.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use egide_auth::{AuthBackend, RootTokenBackend, ServiceTokenBackend, ServiceTokenStore};
//!
//! let store = ServiceTokenStore::new(storage);
//! let backend = ServiceTokenBackend::new(store);
//! let context = backend.validate("svc-token").await?;
//!
//! println!("Authenticated: {}", context.account_id);
//! ```

#![forbid(unsafe_code)]

pub mod backend;
pub mod context;
pub mod error;
pub mod root_token;
pub mod service;
pub mod service_token;

// Re-exports
pub use backend::AuthBackend;
pub use context::{AuthContext, AuthMethod};
pub use error::AuthError;
pub use root_token::{RootTokenBackend, ROOT_TOKEN_HASH_KEY};
pub use service::AuthService;
pub use service_token::{ServiceTokenBackend, ServiceTokenRecord, ServiceTokenStore};
