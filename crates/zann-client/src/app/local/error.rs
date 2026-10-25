use crate::app::{SessionError, SessionErrorKind, SyncError, SyncErrorKind};

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error("vault is locked")]
    Locked,
    #[error("invalid payload: {0}")]
    InvalidPayload(#[source] zann_core::secrets::PayloadError),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("service error: {0}")]
    Service(String),
    #[error("unimplemented: {0}")]
    Unimplemented(String),
    #[error("sync {kind}: {message}")]
    Sync { kind: String, message: String },
}

pub type LocalResult<T> = Result<T, LocalError>;

/// Stable, client-translatable sync error codes. UI layers match these
/// strings the same way they match the wire error kinds; keep every value
/// snake_case and never rename an emitted code.
fn sync_error_kind_code(kind: SyncErrorKind) -> &'static str {
    match kind {
        SyncErrorKind::Cancelled => "sync_cancelled",
        SyncErrorKind::DeadlineExceeded => "sync_deadline_exceeded",
        SyncErrorKind::Session => "sync_session",
        SyncErrorKind::NoLocalTarget => "sync_no_target",
        SyncErrorKind::AccountBindingRequired => "sync_account_binding_required",
        SyncErrorKind::AccountBindingMismatch => "sync_account_binding_mismatch",
        SyncErrorKind::ServerCapabilityMismatch => "sync_server_capability_mismatch",
        SyncErrorKind::AuthenticationBindingRequired => "sync_authentication_binding_required",
        SyncErrorKind::AuthenticationBindingMismatch => "sync_authentication_binding_mismatch",
        SyncErrorKind::Timeout => "network_timeout",
        SyncErrorKind::TransportUnavailable => "server_unreachable",
        SyncErrorKind::TransportRejected => "sync_transport_rejected",
        SyncErrorKind::SessionExpired => "session_expired",
        SyncErrorKind::Protocol => "sync_protocol",
        SyncErrorKind::BodyTooLarge => "sync_body_too_large",
        SyncErrorKind::Crypto => "sync_crypto",
        SyncErrorKind::Local => "db_error",
        SyncErrorKind::ConcurrentLocalChange => "sync_local_conflict",
        SyncErrorKind::ConcurrentRemoteChange => "sync_conflict",
        SyncErrorKind::CommitOutcomeUnknown => "sync_commit_unknown",
        SyncErrorKind::PushUnavailable => "sync_push_unavailable",
        SyncErrorKind::InitialSharedSnapshotUnavailable => "sync_shared_snapshot_unavailable",
        SyncErrorKind::LimitExceeded => "sync_limit_exceeded",
        SyncErrorKind::Internal => "sync_internal",
    }
}

impl From<SyncError> for LocalError {
    fn from(error: SyncError) -> Self {
        let message = match error.status() {
            Some(status) => format!("{error}, http status {status}"),
            None => error.to_string(),
        };
        LocalError::Sync {
            kind: sync_error_kind_code(error.kind()).to_string(),
            message,
        }
    }
}

fn session_error_kind_code(kind: SessionErrorKind) -> &'static str {
    match kind {
        SessionErrorKind::Cancelled => "sync_cancelled",
        SessionErrorKind::DeadlineExceeded => "sync_deadline_exceeded",
        SessionErrorKind::SessionExpired | SessionErrorKind::ReauthenticationRequired => {
            "session_expired"
        }
        SessionErrorKind::TransportUnavailable => "server_unreachable",
        SessionErrorKind::TrustRequired
        | SessionErrorKind::TrustMismatch
        | SessionErrorKind::TrustInvalid => "server_fingerprint_changed",
        SessionErrorKind::InsecureTransport => "insecure_transport",
        SessionErrorKind::Configuration | SessionErrorKind::SessionNotFound => "sync_no_target",
        _ => "sync_session",
    }
}

impl From<SessionError> for LocalError {
    fn from(error: SessionError) -> Self {
        let message = match error.status() {
            Some(status) => format!("{error}, http status {status}"),
            None => error.to_string(),
        };
        LocalError::Sync {
            kind: session_error_kind_code(error.kind()).to_string(),
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sync_error_kind_codes_match_the_client_error_contract() {
        assert_eq!(
            sync_error_kind_code(SyncErrorKind::SessionExpired),
            "session_expired"
        );
        assert_eq!(
            sync_error_kind_code(SyncErrorKind::Timeout),
            "network_timeout"
        );
        assert_eq!(
            sync_error_kind_code(SyncErrorKind::TransportUnavailable),
            "server_unreachable"
        );
        assert_eq!(sync_error_kind_code(SyncErrorKind::Local), "db_error");
        assert_eq!(
            sync_error_kind_code(SyncErrorKind::ConcurrentRemoteChange),
            "sync_conflict"
        );
        assert_eq!(
            sync_error_kind_code(SyncErrorKind::ConcurrentLocalChange),
            "sync_local_conflict"
        );
        assert_eq!(sync_error_kind_code(SyncErrorKind::Crypto), "sync_crypto");
    }

    #[test]
    fn sync_error_kind_codes_are_snake_case_and_unique() {
        let codes = [
            SyncErrorKind::Cancelled,
            SyncErrorKind::DeadlineExceeded,
            SyncErrorKind::Session,
            SyncErrorKind::NoLocalTarget,
            SyncErrorKind::AccountBindingRequired,
            SyncErrorKind::AccountBindingMismatch,
            SyncErrorKind::ServerCapabilityMismatch,
            SyncErrorKind::AuthenticationBindingRequired,
            SyncErrorKind::AuthenticationBindingMismatch,
            SyncErrorKind::Timeout,
            SyncErrorKind::TransportUnavailable,
            SyncErrorKind::TransportRejected,
            SyncErrorKind::SessionExpired,
            SyncErrorKind::Protocol,
            SyncErrorKind::BodyTooLarge,
            SyncErrorKind::Crypto,
            SyncErrorKind::Local,
            SyncErrorKind::ConcurrentLocalChange,
            SyncErrorKind::ConcurrentRemoteChange,
            SyncErrorKind::CommitOutcomeUnknown,
            SyncErrorKind::PushUnavailable,
            SyncErrorKind::InitialSharedSnapshotUnavailable,
            SyncErrorKind::LimitExceeded,
            SyncErrorKind::Internal,
        ]
        .map(sync_error_kind_code);
        let unique: std::collections::HashSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "codes must be unique");
        assert!(
            codes
                .iter()
                .all(|code| code.chars().all(|c| c.is_ascii_lowercase() || c == '_')),
            "codes must be snake_case"
        );
    }
}
