//! Redacted session failures with inspectable diagnostic causes.
use super::*;

/// Redacted session failure. Display and Debug never reflect source error contents.
pub struct SessionError {
    pub(super) operation_id: SessionOperationId,
    pub(super) kind: SessionErrorKind,
    pub(super) status: Option<u16>,
    pub(super) server_code: Option<&'static str>,
    pub(super) completion: OperationCompletion,
    pub(super) cleanup_deferred: bool,
    pub(super) local_revoke_confirmed: bool,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl SessionError {
    pub(crate) fn with_source<E: std::error::Error + Send + Sync + 'static>(
        mut self,
        source: E,
    ) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub(super) fn new(operation: &SessionOperation, kind: SessionErrorKind) -> Self {
        Self {
            operation_id: operation.operation_id,
            kind,
            status: None,
            server_code: None,
            completion: operation.completion(),
            cleanup_deferred: false,
            local_revoke_confirmed: false,
            source: None,
        }
    }

    pub(super) fn from_auth(operation: &SessionOperation, failure: &AuthFailure) -> Self {
        let mut error = Self::new(operation, failure.kind.session_error_kind());
        error.status = failure.status;
        error.server_code = failure.server_code;
        error
    }

    #[cfg(any(feature = "app", all(test, feature = "sync")))]
    pub(crate) fn for_app(operation_id: SessionOperationId, kind: SessionErrorKind) -> Self {
        Self {
            operation_id,
            kind,
            status: None,
            server_code: None,
            completion: OperationCompletion::OnTime,
            cleanup_deferred: false,
            local_revoke_confirmed: false,
            source: None,
        }
    }

    #[cfg(feature = "app")]
    pub(crate) fn from_http_for_app(
        operation_id: SessionOperationId,
        failure: &AuthHttpError,
    ) -> Self {
        let kind = match failure.kind() {
            AuthHttpErrorKind::InvalidEndpoint | AuthHttpErrorKind::Protocol => {
                SessionErrorKind::Protocol
            }
            AuthHttpErrorKind::InsecureTransport => SessionErrorKind::InsecureTransport,
            AuthHttpErrorKind::Timeout | AuthHttpErrorKind::Unavailable => {
                SessionErrorKind::TransportUnavailable
            }
            AuthHttpErrorKind::AmbiguousOutcome => SessionErrorKind::SessionLostRemoteUnknown,
            AuthHttpErrorKind::BodyTooLarge => SessionErrorKind::Protocol,
            AuthHttpErrorKind::SessionExpired => SessionErrorKind::SessionExpired,
            AuthHttpErrorKind::Rejected => SessionErrorKind::TransportRejected,
            AuthHttpErrorKind::Server => SessionErrorKind::TransportUnavailable,
        };
        let mut error = Self::for_app(operation_id, kind);
        error.status = failure.status();
        error.server_code = failure.server_code();
        error
    }

    pub(super) fn terminal(
        operation: &SessionOperation,
        kind: SessionErrorKind,
        status: Option<u16>,
        server_code: Option<&'static str>,
        cleanup_deferred: bool,
        local_revoke_confirmed: bool,
    ) -> Self {
        Self {
            operation_id: operation.operation_id,
            kind,
            status,
            server_code,
            completion: operation.completion(),
            cleanup_deferred,
            local_revoke_confirmed,
            source: None,
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> SessionOperationId {
        self.operation_id
    }

    #[must_use]
    pub fn kind(&self) -> SessionErrorKind {
        self.kind
    }

    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.status
    }

    #[must_use]
    pub fn server_code(&self) -> Option<&'static str> {
        self.server_code
    }

    #[must_use]
    pub fn completion(&self) -> OperationCompletion {
        self.completion
    }

    #[must_use]
    pub fn cleanup_deferred(&self) -> bool {
        self.cleanup_deferred
    }

    #[must_use]
    pub fn local_revoke_confirmed(&self) -> bool {
        self.local_revoke_confirmed
    }
}

impl fmt::Debug for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionError")
            .field("operation_id", &self.operation_id)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("server_code", &self.server_code)
            .field("completion", &self.completion)
            .field("cleanup_deferred", &self.cleanup_deferred)
            .field("local_revoke_confirmed", &self.local_revoke_confirmed)
            .finish()
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "session:{}:{}", self.operation_id, self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, ":status_{status}")?;
        }
        if let Some(code) = self.server_code {
            write!(formatter, ":{code}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source.as_ref() as _)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cause_is_preserved_without_reflection() {
        let (operation, _) = SessionOperation::new(Instant::now() + Duration::from_secs(1));
        let error = SessionError::new(&operation, SessionErrorKind::Configuration)
            .with_source(std::io::Error::other("synthetic-sensitive-diagnostic"));
        assert!(!format!("{error:?} {error}").contains("synthetic-sensitive"));
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "synthetic-sensitive-diagnostic"
        );
    }
}
