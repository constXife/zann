//! Bounded, redirect-free discovery of a server's signed identity.
//!
//! This is the only low-level remote primitive exposed by the clean client
//! crate. It performs a safe read, caps the response body, rejects redirects,
//! and returns data only after the server identity signature has verified.

use std::fmt;

use zann_core::api::system::SystemInfoResponse;

use crate::identity::IdentityVerifiedSystemInfo;
use crate::remote::auth::{AuthHttpError, AuthHttpErrorKind, AuthHttpTransport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeErrorKind {
    InvalidEndpoint,
    Timeout,
    Unavailable,
    Protocol,
    BodyTooLarge,
    Rejected,
    Server,
    InvalidIdentity,
}

impl fmt::Display for ProbeErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::Protocol => "protocol",
            Self::BodyTooLarge => "body_too_large",
            Self::Rejected => "rejected",
            Self::Server => "server",
            Self::InvalidIdentity => "invalid_identity",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeError {
    kind: ProbeErrorKind,
    status: Option<u16>,
}

impl ProbeError {
    #[must_use]
    pub const fn kind(&self) -> ProbeErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    const fn invalid_identity() -> Self {
        Self {
            kind: ProbeErrorKind::InvalidIdentity,
            status: None,
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "server_probe:{}", self.kind)?;
        if let Some(status) = self.status {
            write!(formatter, ":status_{status}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ProbeError {}

impl From<AuthHttpError> for ProbeError {
    fn from(error: AuthHttpError) -> Self {
        let kind = match error.kind() {
            AuthHttpErrorKind::InvalidEndpoint | AuthHttpErrorKind::InsecureTransport => {
                ProbeErrorKind::InvalidEndpoint
            }
            AuthHttpErrorKind::Timeout => ProbeErrorKind::Timeout,
            AuthHttpErrorKind::Unavailable | AuthHttpErrorKind::AmbiguousOutcome => {
                ProbeErrorKind::Unavailable
            }
            AuthHttpErrorKind::BodyTooLarge => ProbeErrorKind::BodyTooLarge,
            AuthHttpErrorKind::Rejected | AuthHttpErrorKind::SessionExpired => {
                ProbeErrorKind::Rejected
            }
            AuthHttpErrorKind::Server => ProbeErrorKind::Server,
            AuthHttpErrorKind::Protocol => ProbeErrorKind::Protocol,
        };
        Self {
            kind,
            status: error.status(),
        }
    }
}

/// Fetch and verify `/v1/system/info` without accepting redirects or an
/// unbounded response body.
pub async fn probe_system_info(endpoint: &str) -> Result<SystemInfoResponse, ProbeError> {
    let transport = AuthHttpTransport::new(endpoint).map_err(ProbeError::from)?;
    let info = transport.system_info().await.map_err(ProbeError::from)?;
    IdentityVerifiedSystemInfo::verify(info)
        .map(IdentityVerifiedSystemInfo::into_inner)
        .map_err(|_| ProbeError::invalid_identity())
}
