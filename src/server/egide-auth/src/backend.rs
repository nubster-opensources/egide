//! Authentication backend trait.

use async_trait::async_trait;

use crate::{AuthContext, AuthError};

/// Trait for authentication backends.
///
/// Implementations validate tokens/credentials and return an [`AuthContext`]
/// on success.
#[async_trait]
pub trait AuthBackend: Send + Sync {
    /// Validates the given token and returns the authentication context.
    ///
    /// # Arguments
    ///
    /// * `token` - The authentication token (JWT, root token, etc.)
    ///
    /// # Returns
    ///
    /// * `Ok(AuthContext)` - If the token is valid
    /// * `Err(AuthError)` - If validation fails
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError>;

    /// Returns the name of this backend for logging/debugging.
    fn name(&self) -> &'static str;
}
