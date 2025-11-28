//! Nubster.Identity authentication backend.
//!
//! Validates JWT tokens issued by Nubster.Identity service.

use async_trait::async_trait;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{AuthBackend, AuthContext, AuthError, AuthMethod};

/// Configuration for Nubster.Identity backend.
#[derive(Debug, Clone)]
pub struct NubsterIdentityConfig {
    /// JWT signing secret (shared with Identity service).
    pub jwt_secret: String,
    /// Expected issuer (e.g., "https://api.nubster.com").
    pub issuer: String,
    /// Expected audience (e.g., "egide").
    pub audience: String,
}

/// JWT claims from Nubster.Identity tokens.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityClaims {
    /// Subject (account ID).
    sub: String,
    /// Email address.
    #[serde(default)]
    email: Option<String>,
    /// First name.
    #[serde(default)]
    given_name: Option<String>,
    /// Last name.
    #[serde(default)]
    family_name: Option<String>,
    /// Issued at (Unix timestamp).
    iat: u64,
    /// Expiration (Unix timestamp).
    exp: u64,
    /// Issuer.
    iss: String,
    /// Audience.
    aud: String,
    /// JWT ID.
    #[serde(default)]
    jti: Option<String>,
}

/// Authentication backend for Nubster.Identity JWT tokens.
///
/// This backend validates JWT tokens signed with HS256 algorithm
/// by the Nubster.Identity service.
pub struct NubsterIdentityBackend {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl NubsterIdentityBackend {
    /// Creates a new Nubster.Identity backend.
    pub fn new(config: NubsterIdentityConfig) -> Self {
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        validation.validate_exp = true;
        validation.validate_nbf = false;

        Self {
            decoding_key,
            validation,
        }
    }
}

#[async_trait]
impl AuthBackend for NubsterIdentityBackend {
    async fn validate(&self, token: &str) -> Result<AuthContext, AuthError> {
        // Decode and validate the JWT
        let token_data = decode::<IdentityClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AuthError::InvalidCredentials
                },
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::InvalidCredentials,
                jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::InvalidCredentials,
                _ => AuthError::InvalidCredentials,
            })?;

        let claims = token_data.claims;

        // Build display name from given_name + family_name
        let display_name = match (&claims.given_name, &claims.family_name) {
            (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
            (Some(first), None) => Some(first.clone()),
            (None, Some(last)) => Some(last.clone()),
            (None, None) => None,
        };

        Ok(AuthContext {
            account_id: claims.sub,
            email: claims.email,
            display_name,
            auth_method: AuthMethod::NubsterIdentity,
            expires_at: Some(claims.exp),
        })
    }

    fn name(&self) -> &'static str {
        "nubster-identity"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn create_test_config() -> NubsterIdentityConfig {
        NubsterIdentityConfig {
            jwt_secret: "test-secret-key-minimum-32-chars!".to_string(),
            issuer: "https://api.nubster.com".to_string(),
            audience: "egide".to_string(),
        }
    }

    fn create_valid_token(config: &NubsterIdentityConfig) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_secs();

        let claims = IdentityClaims {
            sub: "account-12345".to_string(),
            email: Some("test@example.com".to_string()),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            iat: now,
            exp: now + 3600,
            iss: config.issuer.clone(),
            aud: config.audience.clone(),
            jti: Some("token-uuid".to_string()),
        };

        let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        encode(&Header::default(), &claims, &key).expect("failed to encode JWT")
    }

    #[tokio::test]
    async fn test_valid_token() {
        let config = create_test_config();
        let backend = NubsterIdentityBackend::new(config.clone());
        let token = create_valid_token(&config);

        let ctx = backend.validate(&token).await.expect("validation failed");

        assert_eq!(ctx.account_id, "account-12345");
        assert_eq!(ctx.email, Some("test@example.com".to_string()));
        assert_eq!(ctx.display_name, Some("John Doe".to_string()));
        assert_eq!(ctx.auth_method, AuthMethod::NubsterIdentity);
        assert!(ctx.expires_at.is_some());
    }

    #[tokio::test]
    async fn test_expired_token() {
        let config = create_test_config();
        let backend = NubsterIdentityBackend::new(config.clone());

        // Create expired token
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_secs();

        let claims = IdentityClaims {
            sub: "account-12345".to_string(),
            email: None,
            given_name: None,
            family_name: None,
            iat: now - 7200,
            exp: now - 3600, // Expired 1 hour ago
            iss: config.issuer.clone(),
            aud: config.audience.clone(),
            jti: None,
        };

        let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let token = encode(&Header::default(), &claims, &key).expect("failed to encode JWT");

        let result = backend.validate(&token).await;
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let config = create_test_config();
        let backend = NubsterIdentityBackend::new(config.clone());

        // Create token with different secret
        let mut bad_config = config;
        bad_config.jwt_secret = "different-secret-key-minimum-32!".to_string();
        let token = create_valid_token(&bad_config);

        let result = backend.validate(&token).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn test_invalid_issuer() {
        let config = create_test_config();
        let backend = NubsterIdentityBackend::new(config.clone());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_secs();

        let claims = IdentityClaims {
            sub: "account-12345".to_string(),
            email: None,
            given_name: None,
            family_name: None,
            iat: now,
            exp: now + 3600,
            iss: "https://malicious.com".to_string(), // Wrong issuer
            aud: config.audience.clone(),
            jti: None,
        };

        let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let token = encode(&Header::default(), &claims, &key).expect("failed to encode JWT");

        let result = backend.validate(&token).await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }
}
