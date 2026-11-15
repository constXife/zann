use crate::session::SessionError;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcBrowserErrorKind {
    Configuration,
    InvalidProvider,
    Transport,
    Protocol,
    Cancelled,
    DeadlineExceeded,
    AuthorizationRejected,
    Session,
}

pub struct OidcBrowserError {
    repr: Repr,
}

enum Repr {
    /// A failure of the browser flow itself, before Zann saw the token.
    Flow(
        OidcBrowserErrorKind,
        Option<Box<dyn std::error::Error + Send + Sync>>,
    ),
    /// Zann's own answer to the provider token: a rejected login, an
    /// unreachable server or a session that could not be kept.
    Session(SessionError),
}

impl OidcBrowserError {
    pub(super) fn new(kind: OidcBrowserErrorKind) -> Self {
        debug_assert_ne!(kind, OidcBrowserErrorKind::Session);
        Self {
            repr: Repr::Flow(kind, None),
        }
    }

    pub(super) fn caused_by(
        kind: OidcBrowserErrorKind,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            repr: Repr::Flow(kind, Some(Box::new(source))),
        }
    }

    pub(super) fn session(error: SessionError) -> Self {
        Self {
            repr: Repr::Session(error),
        }
    }

    #[must_use]
    pub fn kind(&self) -> OidcBrowserErrorKind {
        match &self.repr {
            Repr::Flow(kind, _) => *kind,
            Repr::Session(_) => OidcBrowserErrorKind::Session,
        }
    }

    /// The session failure behind [`OidcBrowserErrorKind::Session`], so a
    /// caller can report it the way it reports any other login.
    pub fn into_session_error(self) -> Result<SessionError, Self> {
        match self.repr {
            Repr::Session(error) => Ok(error),
            Repr::Flow(..) => Err(self),
        }
    }
}

impl fmt::Debug for OidcBrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("OidcBrowserError");
        debug.field("kind", &self.kind());
        if let Repr::Session(error) = &self.repr {
            debug.field("session", error);
        }
        debug.finish()
    }
}

impl fmt::Display for OidcBrowserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.repr {
            Repr::Session(error) => return write!(formatter, "OIDC session failed: {error}"),
            Repr::Flow(kind, _) => kind,
        };
        formatter.write_str(match kind {
            OidcBrowserErrorKind::Configuration => "OIDC target is not configured",
            OidcBrowserErrorKind::InvalidProvider => "OIDC provider metadata is invalid",
            OidcBrowserErrorKind::Transport => "OIDC provider is unavailable",
            OidcBrowserErrorKind::Protocol => "OIDC protocol response is invalid",
            OidcBrowserErrorKind::Cancelled => "OIDC login was cancelled",
            OidcBrowserErrorKind::DeadlineExceeded => "OIDC login timed out",
            OidcBrowserErrorKind::AuthorizationRejected => "OIDC authorization was rejected",
            OidcBrowserErrorKind::Session => "OIDC session failed",
        })
    }
}

impl std::error::Error for OidcBrowserError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.repr {
            Repr::Session(error) => Some(error),
            Repr::Flow(_, source) => source.as_deref().map(|source| source as _),
        }
    }
}
