//! Authentication context types.

use serde::{Deserialize, Serialize};

/// Method used to authenticate the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Nubster.Identity JWT token.
    NubsterIdentity,
    /// Local user (standalone on-premise).
    Local,
    /// Root token (dev mode / legacy).
    RootToken,
    /// Native service token issued by Egide (machine-to-machine).
    ServiceToken,
}

/// Authenticated user context.
///
/// This struct contains information about the authenticated entity
/// and is passed to handlers after successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Unique account identifier (from JWT `sub` claim or local user ID).
    pub account_id: String,

    /// Email address (for audit purposes, may be None for service accounts).
    pub email: Option<String>,

    /// Display name (first + last name).
    pub display_name: Option<String>,

    /// Authentication method used.
    pub auth_method: AuthMethod,

    /// Token expiration timestamp (Unix seconds).
    pub expires_at: Option<u64>,
}

impl AuthContext {
    /// Creates a root token context (for dev mode).
    pub fn root() -> Self {
        Self {
            account_id: "root".to_string(),
            email: None,
            display_name: Some("Root".to_string()),
            auth_method: AuthMethod::RootToken,
            expires_at: None,
        }
    }

    /// Checks if this is a root context.
    pub fn is_root(&self) -> bool {
        self.auth_method == AuthMethod::RootToken && self.account_id == "root"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_token_method_serializes_snake_case() {
        let json = serde_json::to_string(&AuthMethod::ServiceToken).unwrap();
        assert_eq!(json, "\"service_token\"");
    }

    #[test]
    fn service_token_context_is_not_root() {
        let ctx = AuthContext {
            account_id: "identity".to_string(),
            email: None,
            display_name: None,
            auth_method: AuthMethod::ServiceToken,
            expires_at: None,
        };
        assert!(!ctx.is_root());
    }
}
