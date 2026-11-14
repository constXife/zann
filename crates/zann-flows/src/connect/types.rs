use zann_core::AuthMethod;

pub const LOGIN_TIMEOUT_MS: u64 = 10 * 60 * 1000;
pub const CONNECTION_NAME: &str = "Remote";
pub const PROFILE_NAME: &str = "default";

/// The composition root supplies a unique instance ID. Sequence numbers are
/// allocated by the reducer, so replaying an input trace is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId {
    pub instance: u64,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Probe,
    Trust,
    Password,
    OidcStart,
    OidcFinish,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Stage {
    Server,
    Methods,
    Fingerprint { old: String, new: String },
    Password { register: bool },
    Browser { url: String },
    Complete,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInfo {
    pub methods: Vec<AuthMethod>,
    pub registration_available: bool,
    pub server_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Probe {
    Ready(ServerInfo),
    FingerprintChanged { old: String, new: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connected {
    pub storage_id: String,
    pub has_personal_keys: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Cancelled,
    Message(String),
}

#[derive(Clone)]
pub enum Action {
    Probe {
        url: String,
    },
    TrustFingerprint,
    ChoosePassword,
    SetRegistering {
        register: bool,
    },
    SubmitPassword {
        email: String,
        password: String,
        full_name: Option<String>,
    },
    StartOidc,
    ReopenBrowser,
    CopyBrowserUrl,
    Back,
    Cancel,
}

#[derive(Clone)]
pub enum Completion {
    Probed(Result<Probe, Failure>),
    Trusted(Result<ServerInfo, Failure>),
    Password(Result<Connected, Failure>),
    OidcStarted(Result<String, Failure>),
    OidcFinished(Result<Connected, Failure>),
}

impl Completion {
    pub fn failed(step: Step, failure: Failure) -> Self {
        match step {
            Step::Probe => Self::Probed(Err(failure)),
            Step::Trust => Self::Trusted(Err(failure)),
            Step::Password => Self::Password(Err(failure)),
            Step::OidcStart => Self::OidcStarted(Err(failure)),
            Step::OidcFinish => Self::OidcFinished(Err(failure)),
        }
    }

    pub fn step(&self) -> Step {
        match self {
            Self::Probed(_) => Step::Probe,
            Self::Trusted(_) => Step::Trust,
            Self::Password(_) => Step::Password,
            Self::OidcStarted(_) => Step::OidcStart,
            Self::OidcFinished(_) => Step::OidcFinish,
        }
    }
}

pub enum Effect {
    Probe {
        id: OperationId,
        url: String,
    },
    TrustFingerprint {
        id: OperationId,
    },
    Password {
        id: OperationId,
        email: String,
        password: String,
        full_name: Option<String>,
        register: bool,
    },
    BeginOidc {
        id: OperationId,
    },
    FinishOidc {
        id: OperationId,
    },
    Cancel {
        id: OperationId,
    },
    ResetConnection,
    OpenBrowser {
        id: OperationId,
        url: String,
    },
    CopyBrowserUrl {
        id: OperationId,
        url: String,
    },
    Connected(Connected),
    Closed,
}

impl Effect {
    pub fn operation(&self) -> Option<(OperationId, Step)> {
        match self {
            Self::Probe { id, .. } => Some((*id, Step::Probe)),
            Self::TrustFingerprint { id } => Some((*id, Step::Trust)),
            Self::Password { id, .. } => Some((*id, Step::Password)),
            Self::BeginOidc { id } => Some((*id, Step::OidcStart)),
            Self::FinishOidc { id } => Some((*id, Step::OidcFinish)),
            _ => None,
        }
    }
}

// Inputs/results can contain passwords, authorization URLs or remote diagnostics.
// Keep nested logging safe, not only the outer application's Debug.
macro_rules! redacted_debug {
    ($($ty:ty),* $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )* };
}
redacted_debug!(Action, Completion, Effect, Stage);
