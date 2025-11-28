//! # Egide Auth
//!
//! Authentication and authorization for Egide.
//!
//! ## Supported Backends
//!
//! - **Nubster.Identity**: JWT tokens from Nubster.Identity service (Cloud + OnPrem Workspace)
//! - **Root Token**: Legacy single-token auth (dev mode, standalone)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use egide_auth::{AuthBackend, NubsterIdentityBackend, NubsterIdentityConfig};
//!
//! let config = NubsterIdentityConfig {
//!     jwt_secret: "your-secret".to_string(),
//!     issuer: "https://api.nubster.com".to_string(),
//!     audience: "egide".to_string(),
//! };
//!
//! let backend = NubsterIdentityBackend::new(config);
//! let context = backend.validate("jwt-token").await?;
//!
//! println!("Authenticated: {}", context.account_id);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod context;
pub mod error;
pub mod nubster_identity;
pub mod root_token;

// Re-exports
pub use backend::AuthBackend;
pub use context::{AuthContext, AuthMethod};
pub use error::AuthError;
pub use nubster_identity::{NubsterIdentityBackend, NubsterIdentityConfig};
pub use root_token::{RootTokenBackend, RootTokenHashFn};
