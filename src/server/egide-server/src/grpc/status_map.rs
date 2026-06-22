//! Maps transport-agnostic [`ServiceError`] values to gRPC [`tonic::Status`].

use egide_api::ServiceError;
use tonic::Status;

/// Maps a transport-agnostic service error to a gRPC status.
///
/// The mapping mirrors the HTTP status choices made by the REST handlers so
/// that both transports behave consistently from the client's perspective.
#[must_use]
pub fn to_status(e: ServiceError) -> Status {
    match e {
        ServiceError::NotFound => Status::not_found("not found"),
        ServiceError::Conflict => Status::already_exists("already exists"),
        ServiceError::BadRequest(m) => Status::invalid_argument(m),
        ServiceError::Forbidden(m) => Status::permission_denied(m),
        ServiceError::Sealed => Status::unavailable("vault is sealed"),
        ServiceError::DecryptionFailed => Status::invalid_argument("decryption failed"),
        ServiceError::Internal(m) => Status::internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn not_found_maps_to_not_found_code() {
        assert_eq!(to_status(ServiceError::NotFound).code(), Code::NotFound);
    }

    #[test]
    fn conflict_maps_to_already_exists() {
        assert_eq!(
            to_status(ServiceError::Conflict).code(),
            Code::AlreadyExists
        );
    }

    #[test]
    fn bad_request_maps_to_invalid_argument() {
        let s = to_status(ServiceError::BadRequest("bad input".into()));
        assert_eq!(s.code(), Code::InvalidArgument);
        assert!(s.message().contains("bad input"));
    }

    #[test]
    fn forbidden_maps_to_permission_denied() {
        let s = to_status(ServiceError::Forbidden("root required".into()));
        assert_eq!(s.code(), Code::PermissionDenied);
    }

    #[test]
    fn sealed_maps_to_unavailable() {
        assert_eq!(to_status(ServiceError::Sealed).code(), Code::Unavailable);
    }

    #[test]
    fn decryption_failed_maps_to_invalid_argument() {
        assert_eq!(
            to_status(ServiceError::DecryptionFailed).code(),
            Code::InvalidArgument
        );
    }

    #[test]
    fn internal_maps_to_internal() {
        let s = to_status(ServiceError::Internal("db error".into()));
        assert_eq!(s.code(), Code::Internal);
        assert!(s.message().contains("db error"));
    }
}
