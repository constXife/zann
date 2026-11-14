use super::{flow, records::*};
use crate::AuthMethodFfi;

impl From<ConnectOperationFfi> for flow::OperationId {
    fn from(id: ConnectOperationFfi) -> Self {
        Self {
            instance: id.instance,
            sequence: id.sequence,
        }
    }
}
impl From<flow::OperationId> for ConnectOperationFfi {
    fn from(id: flow::OperationId) -> Self {
        Self {
            instance: id.instance,
            sequence: id.sequence,
        }
    }
}
impl From<ConnectStepFfi> for flow::Step {
    fn from(step: ConnectStepFfi) -> Self {
        match step {
            ConnectStepFfi::Probe => Self::Probe,
            ConnectStepFfi::Trust => Self::Trust,
            ConnectStepFfi::Password => Self::Password,
            ConnectStepFfi::OidcStart => Self::OidcStart,
            ConnectStepFfi::OidcFinish => Self::OidcFinish,
        }
    }
}
impl From<ConnectServerFfi> for flow::ServerInfo {
    fn from(info: ConnectServerFfi) -> Self {
        Self {
            methods: info
                .methods
                .into_iter()
                .map(|method| match method {
                    AuthMethodFfi::Password => zann_client::app::AuthMethod::Password,
                    AuthMethodFfi::Oidc => zann_client::app::AuthMethod::Oidc,
                    AuthMethodFfi::ServiceAccount => zann_client::app::AuthMethod::ServiceAccount,
                })
                .collect(),
            registration_available: info.registration_available,
            server_name: info.server_name,
        }
    }
}
impl From<ConnectActionFfi> for flow::Action {
    fn from(action: ConnectActionFfi) -> Self {
        match action {
            ConnectActionFfi::Probe { url } => Self::Probe { url },
            ConnectActionFfi::TrustFingerprint => Self::TrustFingerprint,
            ConnectActionFfi::ChoosePassword => Self::ChoosePassword,
            ConnectActionFfi::SetRegistering { register } => Self::SetRegistering { register },
            ConnectActionFfi::SubmitPassword {
                email,
                password,
                full_name,
            } => Self::SubmitPassword {
                email,
                password,
                full_name,
            },
            ConnectActionFfi::StartOidc => Self::StartOidc,
            ConnectActionFfi::ReopenBrowser => Self::ReopenBrowser,
            ConnectActionFfi::CopyBrowserUrl => Self::CopyBrowserUrl,
            ConnectActionFfi::Back => Self::Back,
            ConnectActionFfi::Cancel => Self::Cancel,
        }
    }
}
impl ConnectCompletionFfi {
    pub(super) fn into_parts(self) -> (flow::OperationId, flow::Completion) {
        use flow::{Completion as C, Connected, Failure, Probe};
        let (id, result) = match self {
            Self::Probed { id, probe } => (
                id,
                C::Probed(Ok(match probe {
                    ConnectProbeFfi::Ready { info } => Probe::Ready(info.into()),
                    ConnectProbeFfi::FingerprintChanged { old, new } => {
                        Probe::FingerprintChanged { old, new }
                    }
                })),
            ),
            Self::Trusted { id, info } => (id, C::Trusted(Ok(info.into()))),
            Self::Password {
                id,
                storage_id,
                has_personal_keys,
            } => (
                id,
                C::Password(Ok(Connected {
                    storage_id,
                    has_personal_keys,
                })),
            ),
            Self::OidcFinished {
                id,
                storage_id,
                has_personal_keys,
            } => (
                id,
                C::OidcFinished(Ok(Connected {
                    storage_id,
                    has_personal_keys,
                })),
            ),
            Self::OidcStarted { id, url } => (id, C::OidcStarted(Ok(url))),
            Self::Failed { id, step, message } => {
                let failure = message.map(Failure::Message).unwrap_or(Failure::Cancelled);
                (
                    id,
                    match step {
                        ConnectStepFfi::Probe => C::Probed(Err(failure)),
                        ConnectStepFfi::Trust => C::Trusted(Err(failure)),
                        ConnectStepFfi::Password => C::Password(Err(failure)),
                        ConnectStepFfi::OidcStart => C::OidcStarted(Err(failure)),
                        ConnectStepFfi::OidcFinish => C::OidcFinished(Err(failure)),
                    },
                )
            }
        };
        (id.into(), result)
    }
}
impl From<&flow::Snapshot> for ConnectSnapshotFfi {
    fn from(state: &flow::Snapshot) -> Self {
        Self {
            stage: match &state.stage {
                flow::Stage::Server => ConnectStageFfi::Server,
                flow::Stage::Methods => ConnectStageFfi::Methods,
                flow::Stage::Fingerprint { old, new } => ConnectStageFfi::Fingerprint {
                    old: old.clone(),
                    new: new.clone(),
                },
                flow::Stage::Password { register } => ConnectStageFfi::Password {
                    register: *register,
                },
                flow::Stage::Browser { url } => ConnectStageFfi::Browser { url: url.clone() },
                flow::Stage::Complete => ConnectStageFfi::Complete,
                flow::Stage::Closed => ConnectStageFfi::Closed,
            },
            server_url: state.server_url.clone(),
            methods: state.methods.iter().copied().map(Into::into).collect(),
            registration_available: state.registration_available,
            server_name: state.server_name.clone(),
            busy: state.busy,
            error: state.error.clone(),
        }
    }
}
impl From<flow::Effect> for ConnectEffectFfi {
    fn from(effect: flow::Effect) -> Self {
        match effect {
            flow::Effect::Probe { id, url } => Self::Probe {
                id: id.into(),
                url,
                connection_name: flow::CONNECTION_NAME.into(),
                profile_name: flow::PROFILE_NAME.into(),
            },
            flow::Effect::TrustFingerprint { id } => Self::TrustFingerprint { id: id.into() },
            flow::Effect::Password {
                id,
                email,
                password,
                full_name,
                register,
            } => Self::Password {
                id: id.into(),
                email,
                password,
                full_name,
                register,
                timeout_ms: flow::LOGIN_TIMEOUT_MS,
            },
            flow::Effect::BeginOidc { id } => Self::BeginOidc {
                id: id.into(),
                timeout_ms: flow::LOGIN_TIMEOUT_MS,
            },
            flow::Effect::FinishOidc { id } => Self::FinishOidc { id: id.into() },
            flow::Effect::Cancel { id } => Self::Cancel { id: id.into() },
            flow::Effect::ResetConnection => Self::ResetConnection,
            flow::Effect::OpenBrowser { id, url } => Self::OpenBrowser { id: id.into(), url },
            flow::Effect::CopyBrowserUrl { id, url } => Self::CopyBrowserUrl { id: id.into(), url },
            flow::Effect::Connected(connected) => Self::Connected {
                storage_id: connected.storage_id,
                has_personal_keys: connected.has_personal_keys,
            },
            flow::Effect::Closed => Self::Closed,
        }
    }
}
