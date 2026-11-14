use crate::AuthMethodFfi;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConnectOperationFfi {
    pub instance: u64,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectStepFfi {
    Probe,
    Trust,
    Password,
    OidcStart,
    OidcFinish,
}
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectStageFfi {
    Server,
    Methods,
    Fingerprint { old: String, new: String },
    Password { register: bool },
    Browser { url: String },
    Complete,
    Closed,
}
#[derive(Clone, uniffi::Record)]
pub struct ConnectServerFfi {
    pub methods: Vec<AuthMethodFfi>,
    pub registration_available: bool,
    pub server_name: Option<String>,
}
#[derive(Clone, uniffi::Enum)]
pub enum ConnectProbeFfi {
    Ready { info: ConnectServerFfi },
    FingerprintChanged { old: String, new: String },
}
#[derive(Clone, uniffi::Record)]
pub struct ConnectSnapshotFfi {
    pub stage: ConnectStageFfi,
    pub server_url: String,
    pub methods: Vec<AuthMethodFfi>,
    pub registration_available: bool,
    pub server_name: Option<String>,
    pub busy: bool,
    pub error: Option<String>,
}
#[derive(Clone, uniffi::Enum)]
pub enum ConnectActionFfi {
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
#[derive(Clone, uniffi::Enum)]
pub enum ConnectCompletionFfi {
    Probed {
        id: ConnectOperationFfi,
        probe: ConnectProbeFfi,
    },
    Trusted {
        id: ConnectOperationFfi,
        info: ConnectServerFfi,
    },
    Password {
        id: ConnectOperationFfi,
        storage_id: String,
        has_personal_keys: bool,
    },
    OidcStarted {
        id: ConnectOperationFfi,
        url: String,
    },
    OidcFinished {
        id: ConnectOperationFfi,
        storage_id: String,
        has_personal_keys: bool,
    },
    Failed {
        id: ConnectOperationFfi,
        step: ConnectStepFfi,
        message: Option<String>,
    },
}
#[derive(uniffi::Enum)]
pub enum ConnectEffectFfi {
    Probe {
        id: ConnectOperationFfi,
        url: String,
        connection_name: String,
        profile_name: String,
    },
    TrustFingerprint {
        id: ConnectOperationFfi,
    },
    Password {
        id: ConnectOperationFfi,
        email: String,
        password: String,
        full_name: Option<String>,
        register: bool,
        timeout_ms: u64,
    },
    BeginOidc {
        id: ConnectOperationFfi,
        timeout_ms: u64,
    },
    FinishOidc {
        id: ConnectOperationFfi,
    },
    Cancel {
        id: ConnectOperationFfi,
    },
    ResetConnection,
    OpenBrowser {
        id: ConnectOperationFfi,
        url: String,
    },
    CopyBrowserUrl {
        id: ConnectOperationFfi,
        url: String,
    },
    Connected {
        storage_id: String,
        has_personal_keys: bool,
    },
    Closed,
}

macro_rules! redacted_debug {
    ($($ty:ty),* $(,)?) => { $(impl std::fmt::Debug for $ty {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })* };
}
redacted_debug!(
    ConnectActionFfi,
    ConnectCompletionFfi,
    ConnectEffectFfi,
    ConnectSnapshotFfi,
    ConnectStageFfi
);
