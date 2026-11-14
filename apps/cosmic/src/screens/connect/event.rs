//! Scoped Connect inputs, results and shell effects.

use cosmic::iced::Task;

use super::{LoginOutcome, ServerProbe};

#[derive(Clone)]
pub enum Message {
    UrlInput(String),
    Probe,
    Probed(Result<ServerProbe, String>),
    ChoosePassword,
    EmailInput(String),
    FullNameInput(String),
    PasswordInput(String),
    TogglePassword,
    SubmitPassword,
    StartOidc,
    OidcStarted(Result<String, String>),
    OpenAuthUrl,
    CopyAuthUrl,
    TrustFingerprint,
    FingerprintTrusted(Result<(), String>),
    Outcome(Result<LoginOutcome, String>),
    Poll,
    Cancel,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectMessage(<redacted>)")
    }
}

/// Captures the originating screen for inputs, queued transitions and results.
#[derive(Clone, Debug)]
pub struct Event {
    pub(super) generation: u64,
    pub(super) message: Message,
}

pub enum Outcome {
    None,
    Task(Task<Event>),
    Copy(String),
    OpenUrl(String),
    /// The user backed out of connecting.
    Cancelled,
    /// A login finished; the shell rebuilds the session and moves on to the
    /// master password.
    Connected {
        storage_id: String,
        has_personal_keys: bool,
    },
}
