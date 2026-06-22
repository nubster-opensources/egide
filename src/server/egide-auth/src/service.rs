//! Authentication service combinator.
//!
//! Composes multiple [`AuthBackend`] implementations and validates tokens
//! against each in order. The first success wins; [`AuthError::TokenExpired`]
//! is treated as a terminal error and stops the chain immediately.

use async_trait::async_trait;

use crate::{AuthBackend, AuthContext, AuthError};

/// Combined authentication service that tries multiple backends.
pub struct AuthService {
    backends: Vec<Box<dyn AuthBackend>>,
}

impl AuthService {
    /// Creates a new auth service with the given backends.
    #[must_use]
    pub fn new(backends: Vec<Box<dyn AuthBackend>>) -> Self {
        Self { backends }
    }

    /// Validates a token against all configured backends.
    pub async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        for backend in &self.backends {
            match backend.validate(token).await {
                Ok(ctx) => {
                    tracing::debug!(backend = backend.name(), account = %ctx.account_id, "Auth success");
                    return Ok(ctx);
                },
                Err(AuthError::TokenExpired) => {
                    // Token expired is a definitive error, don't try other backends
                    return Err(AuthError::TokenExpired);
                },
                Err(_) => {
                    // Try next backend
                },
            }
        }
        Err(AuthError::InvalidCredentials)
    }
}

#[async_trait]
impl AuthBackend for AuthService {
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        AuthService::validate(self, token).await
    }

    fn name(&self) -> &'static str {
        "auth-service"
    }
}
