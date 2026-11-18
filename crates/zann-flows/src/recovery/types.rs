use zann_core::api::account_access::PasskeyMode;
use zann_core::recovery::RecoveryState;

pub use crate::connect::Failure;
pub use crate::OperationId;

/// Native preparation custody. The successor code is a secret: implementors
/// MUST redact `Debug` and zeroize it on drop.
pub trait Preparation {
    fn successor_code(&self) -> &str;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Prepare,
    Consume,
    Enroll,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Terminal {
    Completed,
    Stopped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub name: String,
    pub mode: PasskeyMode,
}

/// Value-only projection of the server recovery view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Progress {
    pub state: RecoveryState,
    pub candidate: Option<Candidate>,
}

/// An armed recovery is journaled before its response arrives. The handle
/// therefore survives a lost consume response so it can be retried or resumed.
pub struct Consumed<H> {
    pub handle: H,
    pub progress: Result<Progress, Failure>,
}

pub enum Reply<P, H> {
    Prepared { preparation: P, pending: Vec<H> },
    Consumed(Consumed<H>),
    Enrolled,
}

impl<P, H> Reply<P, H> {
    pub(super) fn fits(&self, step: Step) -> bool {
        matches!(
            (self, step),
            (Self::Prepared { .. }, Step::Prepare)
                | (Self::Consumed(_), Step::Consume)
                | (Self::Enrolled, Step::Enroll)
        )
    }
}

/// Secret drafts (old code, successor confirmation, encryption password) stay
/// in native custody. The flow only borrows the confirmation to admit consume.
pub enum Action<'a> {
    SetLocator(String),
    SetName(String),
    SetMode(PasskeyMode),
    SetRestart(bool),
    Prepare,
    Consume { confirmation: &'a str },
    RetryConsume,
    ResumeCurrent,
    ResumePending(usize),
    Enroll { pairing: String },
    Back,
}

/// Work effects name which native secret drafts the executor attaches:
/// `Consume` takes the confirmation and old code, `RetryConsume` the old code,
/// `Enroll` the encryption password only for `PasskeyMode::VaultUnlock`.
pub enum Effect<P, H> {
    Prepare {
        id: OperationId,
        locator: String,
    },
    Consume {
        id: OperationId,
        preparation: P,
    },
    RetryConsume {
        id: OperationId,
        handle: H,
    },
    Resume {
        id: OperationId,
        handle: H,
    },
    Enroll {
        id: OperationId,
        handle: H,
        restart: bool,
        name: String,
        mode: PasskeyMode,
        pairing: String,
    },
    Cancel {
        id: OperationId,
    },
    Closed,
}

impl<P, H> Effect<P, H> {
    pub fn operation(&self) -> Option<OperationId> {
        match self {
            Self::Prepare { id, .. }
            | Self::Consume { id, .. }
            | Self::RetryConsume { id, .. }
            | Self::Resume { id, .. }
            | Self::Enroll { id, .. } => Some(*id),
            Self::Cancel { .. } | Self::Closed => None,
        }
    }
}

pub struct Snapshot<'a, H> {
    pub phase: Phase<'a, H>,
    pub busy: bool,
    pub error: Option<&'a str>,
}

pub enum Phase<'a, H> {
    Locate {
        locator: &'a str,
    },
    Confirm {
        successor_code: &'a str,
        pending: &'a [H],
    },
    Recover {
        /// `false` after a lost or failed consume: offer retry/resume only.
        consumed: bool,
        /// A registered candidate fixes name and mode unless restarting.
        candidate: bool,
        restart: bool,
        editable: bool,
        name: &'a str,
        mode: PasskeyMode,
        password_required: bool,
    },
    Completed,
    Stopped,
}

macro_rules! redacted_debug {
    ($($ty:ident < $($g:ident),* >),* $(,)?) => { $(
        impl<$($g),*> std::fmt::Debug for $ty<$($g),*> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )* };
}
redacted_debug!(Effect<P, H>, Reply<P, H>);
impl std::fmt::Debug for Action<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Action(<redacted>)")
    }
}
