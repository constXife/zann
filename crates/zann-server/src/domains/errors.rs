use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ServiceError {
    #[error("forbidden_no_body")]
    ForbiddenNoBody,
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    #[error("unauthorized: {0}")]
    Unauthorized(&'static str),
    #[error("bad_request: {0}")]
    BadRequest(&'static str),
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("not_found")]
    NotFound,
    #[error("payload_too_large: {0}")]
    PayloadTooLarge(&'static str),
    #[error("db_error")]
    DbError,
    #[error("internal: {0}")]
    Internal(&'static str),
    #[error("no_changes")]
    NoChanges,
    #[error("invalid_password")]
    InvalidPassword,
    #[error("invalid_credentials")]
    InvalidCredentials,
    #[error("kdf_error")]
    Kdf,
    #[error("device_required")]
    DeviceRequired,
    #[error("policy_mismatch")]
    PolicyMismatch { existing: String, requested: String },
}
