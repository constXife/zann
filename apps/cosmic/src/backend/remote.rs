//! Executes shared Connect effects against canonical application capabilities.
use super::active_database_location;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use zann_client::app::{
    AppClient, ClientId, ConnectionTrustChallenge, LoginPassword, PasswordLoginInputError,
    PasswordLoginRequest, PasswordRegistrationRequest, PrepareConnectionOutcome,
    PreparedConnection, SessionCancellationHandle, SessionClient, SessionError, SessionErrorKind,
    SessionOperation,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client::oidc::{OidcBrowserErrorKind, OidcBrowserLogin};
use zann_client_sqlite::local_vault::initialize_database;
use zann_client_sqlite::SqliteSyncStoreFactory;
use zann_flows::connect::{
    Completion, Connected, Effect, Failure, OperationId, Probe, ServerInfo, Step,
};
mod plan;
pub use plan::{Plan, Reply};

pub struct Remote {
    runtime: Runtime,
    client: Arc<AppClient>,
    state: Mutex<ExecutionState>,
}

#[derive(Default)]
struct ExecutionState {
    closed: bool,
    prepared: Option<PreparedConnection>,
    challenge: Option<ConnectionTrustChallenge>,
    browser: Option<OidcBrowserLogin>,
    active: Option<(OperationId, SessionCancellationHandle)>,
}

impl Remote {
    pub fn new() -> Result<Self, String> {
        let location = active_database_location()?;
        let client_root = location.client_root().to_path_buf();
        std::fs::create_dir_all(&client_root).map_err(|err| err.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&client_root, std::fs::Permissions::from_mode(0o700))
                .map_err(|err| err.to_string())?;
        }
        let runtime = Runtime::new().map_err(|err| err.to_string())?;
        runtime
            .block_on(initialize_database(location.file_location()))
            .map_err(|err| err.to_string())?;

        let credentials = Arc::new(OsCredentialStore::system_default());
        let sync_factory =
            Arc::new(SqliteSyncStoreFactory::new(location.path()).map_err(|err| err.to_string())?);
        let client_id = ClientId::new("desktop").map_err(|err| err.to_string())?;
        let client = Arc::new(AppClient::new(
            zann_client::app::ClientPaths::new(&client_root),
            credentials,
            SessionClient::new(client_id),
            sync_factory,
        ));
        client
            .initialize(&OsLegacyCredentialSource::system_default())
            .map_err(|err| err.to_string())?;
        Ok(Self {
            runtime,
            client,
            state: Mutex::new(ExecutionState::default()),
        })
    }

    /// Called on the UI composition thread before a task can be scheduled.
    pub fn plan(self: &Arc<Self>, effect: Effect) -> Result<Plan, String> {
        Plan::new(Arc::clone(self), effect)
    }

    /// The screen validates the shared operation ID before installing handles.
    pub fn accept(&self, reply: Reply) -> Option<Completion> {
        let result = reply.result.lock().expect("reply lock poisoned").take()?;
        let mut state = self.state.lock().expect("Connect executor lock poisoned");
        if state.closed {
            return None;
        }
        Some(match result {
            Err(failure) => Completion::failed(reply.step, failure),
            Ok(plan::ResultValue::Probed(outcome)) => match outcome {
                PrepareConnectionOutcome::Ready(prepared) => {
                    let info = server_info(&prepared);
                    state.prepared = Some(prepared);
                    Completion::Probed(Ok(Probe::Ready(info)))
                }
                PrepareConnectionOutcome::FingerprintChanged(challenge) => {
                    let probe = Probe::FingerprintChanged {
                        old: challenge.old_fingerprint().to_string(),
                        new: challenge.new_fingerprint().to_string(),
                    };
                    state.challenge = Some(*challenge);
                    Completion::Probed(Ok(probe))
                }
            },
            Ok(plan::ResultValue::Trusted(prepared)) => {
                let info = server_info(&prepared);
                state.prepared = Some(prepared);
                Completion::Trusted(Ok(info))
            }
            Ok(plan::ResultValue::Browser(login)) => {
                let url = login.authorization_url().to_string();
                state.browser = Some(*login);
                Completion::OidcStarted(Ok(url))
            }
            Ok(plan::ResultValue::Connected(connected)) => match reply.step {
                Step::Password => Completion::Password(Ok(connected)),
                Step::OidcFinish => Completion::OidcFinished(Ok(connected)),
                _ => unreachable!("only authentication plans return Connected"),
            },
        })
    }

    pub fn cancel(&self, id: OperationId) {
        let mut state = self.state.lock().expect("Connect executor lock poisoned");
        if state
            .active
            .as_ref()
            .is_some_and(|(current, _)| *current == id)
        {
            if let Some((_, cancellation)) = state.active.take() {
                cancellation.cancel();
            }
            state.browser = None;
        }
    }

    pub fn reset(&self) {
        let mut state = self.state.lock().expect("Connect executor lock poisoned");
        state.prepared = None;
        state.challenge = None;
        state.browser = None;
    }

    pub fn close(&self) {
        let mut state = self.state.lock().expect("Connect executor lock poisoned");
        state.closed = true;
        if let Some((_, cancellation)) = state.active.take() {
            cancellation.cancel();
        }
        state.prepared = None;
        state.challenge = None;
        state.browser = None;
    }
}

fn server_info(prepared: &PreparedConnection) -> ServerInfo {
    ServerInfo {
        methods: prepared.auth_methods().to_vec(),
        registration_available: prepared.registration_available(),
        server_name: prepared.server_name().map(str::to_string),
    }
}

#[cfg(test)]
mod tests;
