//! RFC 9457 Problem Details responses.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// An RFC 9457 problem detail.
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_uri: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
}

impl Problem {
    /// Builds a problem from a status code and a detail message.
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            type_uri: "about:blank".to_string(),
            title: status.canonical_reason().unwrap_or("Error").to_string(),
            status: status.as_u16(),
            detail: detail.into(),
        }
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(self),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carries_status_and_title() {
        let p = Problem::new(StatusCode::FORBIDDEN, "nope");
        assert_eq!(p.status, 403);
        assert_eq!(p.title, "Forbidden");
        assert_eq!(p.detail, "nope");
    }
}
