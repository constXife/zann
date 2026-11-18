//! Captures capabilities and registers cancellation before worker dispatch.
use super::*;
use zann_flows::connect::{CONNECTION_NAME, LOGIN_TIMEOUT_MS};

pub struct Plan {
    pub id: OperationId,
    pub step: Step,
    remote: Arc<Remote>,
    cancellation: SessionCancellationHandle,
    work: Work,
}

enum Work {
    Probe(String, Option<String>),
    Trust(ConnectionTrustChallenge),
    Password {
        prepared: PreparedConnection,
        email: String,
        password: String,
        full_name: Option<String>,
        register: bool,
        operation: SessionOperation,
    },
    Passkey {
        prepared: PreparedConnection,
        provider: Arc<dyn super::AccountCeremonyProvider>,
        operation: SessionOperation,
    },
    Begin {
        prepared: PreparedConnection,
        operation: SessionOperation,
    },
    Finish {
        login: OidcBrowserLogin,
        storage_id: String,
    },
}

pub(super) enum ResultValue {
    Probed(PrepareConnectionOutcome),
    Trusted(PreparedConnection),
    Browser(Box<OidcBrowserLogin>),
    Connected(Connected),
    Passkey(Connected, Box<super::PasskeyVaultBootstrap>),
}

#[derive(Clone)]
pub struct Reply {
    pub id: OperationId,
    pub step: Step,
    pub(super) result: Arc<Mutex<Option<Result<ResultValue, Failure>>>>,
}
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConnectReply(<redacted>)")
    }
}

impl Plan {
    pub(super) fn new(remote: Arc<Remote>, effect: Effect) -> Result<Self, String> {
        let mut state = remote.state.lock().expect("Connect executor lock poisoned");
        if state.closed {
            return Err("connection flow was cancelled".into());
        }
        let mut operation = None;
        let id = match &effect {
            Effect::Probe { id, .. }
            | Effect::TrustFingerprint { id }
            | Effect::Password { id, .. }
            | Effect::Passkey { id }
            | Effect::BeginOidc { id }
            | Effect::FinishOidc { id } => *id,
            _ => return Err("not a Connect work effect".into()),
        };
        let cancellation = if matches!(effect, Effect::FinishOidc { .. }) {
            state
                .active
                .as_ref()
                .filter(|(current, _)| *current == id)
                .map(|(_, cancellation)| cancellation.clone())
                .ok_or("OIDC operation is no longer current")?
        } else {
            if let Some((_, previous)) = state.active.take() {
                previous.cancel();
            }
            let (next, cancellation) =
                SessionOperation::new(Instant::now() + Duration::from_millis(LOGIN_TIMEOUT_MS));
            operation = Some(next);
            state.active = Some((id, cancellation.clone()));
            cancellation
        };
        let (step, work) = match effect {
            Effect::Probe {
                url, storage_id, ..
            } => (Step::Probe, Work::Probe(url, storage_id)),
            Effect::TrustFingerprint { .. } => (
                Step::Trust,
                Work::Trust(
                    state
                        .challenge
                        .take()
                        .ok_or("fingerprint challenge is no longer current")?,
                ),
            ),
            Effect::Password {
                email,
                password,
                full_name,
                register,
                ..
            } => (
                Step::Password,
                Work::Password {
                    prepared: state
                        .prepared
                        .clone()
                        .ok_or("server connection has not been prepared")?,
                    email,
                    password,
                    full_name,
                    register,
                    operation: operation.expect("new password operation"),
                },
            ),
            Effect::Passkey { .. } => (
                Step::Passkey,
                Work::Passkey {
                    prepared: state
                        .prepared
                        .clone()
                        .ok_or("server connection has not been prepared")?,
                    provider: state
                        .provider
                        .clone()
                        .ok_or("select a paired browser first")?,
                    operation: operation.expect("new passkey operation"),
                },
            ),
            Effect::BeginOidc { .. } => (
                Step::OidcStart,
                Work::Begin {
                    prepared: state
                        .prepared
                        .clone()
                        .ok_or("server connection has not been prepared")?,
                    operation: operation.expect("new OIDC operation"),
                },
            ),
            Effect::FinishOidc { .. } => (
                Step::OidcFinish,
                Work::Finish {
                    login: state
                        .browser
                        .take()
                        .ok_or("OIDC listener is no longer current")?,
                    storage_id: state
                        .prepared
                        .as_ref()
                        .ok_or("server connection has not been prepared")?
                        .storage_id()
                        .to_string(),
                },
            ),
            _ => unreachable!("work effect checked above"),
        };
        drop(state);
        Ok(Self {
            id,
            step,
            remote,
            cancellation,
            work,
        })
    }

    pub fn run(self) -> Reply {
        let result = if self.cancellation.is_cancelled() {
            Err(Failure::Cancelled)
        } else {
            Self::execute(&self.remote, self.work)
        };
        Reply {
            id: self.id,
            step: self.step,
            result: Arc::new(Mutex::new(Some(result))),
        }
    }

    fn execute(remote: &Remote, work: Work) -> Result<ResultValue, Failure> {
        remote.runtime.block_on(async {
            let (access, storage_id) = match work {
                Work::Probe(url, storage_id) => {
                    return remote
                        .client
                        .prepare_account_connection(&url, CONNECTION_NAME, storage_id.as_deref())
                        .await
                        .map(ResultValue::Probed)
                        .map_err(session_failure)
                }
                Work::Trust(challenge) => {
                    return remote
                        .client
                        .trust_connection(challenge)
                        .map(ResultValue::Trusted)
                        .map_err(session_failure)
                }
                Work::Password {
                    prepared,
                    email,
                    password,
                    full_name,
                    register,
                    operation,
                } => {
                    let password = LoginPassword::new(password).map_err(input_failure)?;
                    let access = if register {
                        let request = PasswordRegistrationRequest::new(
                            prepared.target().clone(),
                            email,
                            password,
                            full_name,
                        )
                        .map_err(input_failure)?;
                        remote.client.password_register(request, operation).await
                    } else {
                        let request =
                            PasswordLoginRequest::new(prepared.target().clone(), email, password)
                                .map_err(input_failure)?;
                        remote.client.password_login(request, operation).await
                    }
                    .map_err(session_failure)?;
                    (access, prepared.storage_id().to_string())
                }
                Work::Passkey {
                    prepared,
                    provider,
                    operation,
                } => {
                    let outcome = remote
                        .client
                        .passkey_login(prepared.target().clone(), provider, operation)
                        .await
                        .map_err(session_failure)?;
                    let status = remote
                        .client
                        .personal_vault_status(&outcome.access)
                        .await
                        .map_err(session_failure)?;
                    return Ok(ResultValue::Passkey(
                        Connected {
                            storage_id: prepared.storage_id().to_string(),
                            has_personal_keys: status.personal_key_envelopes_present(),
                        },
                        Box::new(outcome.vault),
                    ));
                }
                Work::Begin {
                    prepared,
                    operation,
                } => {
                    return remote
                        .client
                        .begin_oidc_login(
                            prepared.target().clone(),
                            operation,
                            OidcCallback::Loopback,
                        )
                        .await
                        .map(|login| ResultValue::Browser(Box::new(login)))
                        .map_err(|error| {
                            if error.kind() == OidcBrowserErrorKind::Cancelled {
                                Failure::Cancelled
                            } else {
                                Failure::Message(error.to_string())
                            }
                        })
                }
                Work::Finish { login, storage_id } => {
                    let access = login.finish(&remote.client).await.map_err(|error| {
                        if error.kind() == OidcBrowserErrorKind::Cancelled {
                            Failure::Cancelled
                        } else {
                            Failure::Message(error.to_string())
                        }
                    })?;
                    (access, storage_id)
                }
            };
            let status = remote
                .client
                .personal_vault_status(&access)
                .await
                .map_err(session_failure)?;
            Ok(ResultValue::Connected(Connected {
                storage_id,
                has_personal_keys: status.personal_key_envelopes_present(),
            }))
        })
    }
}

fn session_failure(error: SessionError) -> Failure {
    if error.kind() == SessionErrorKind::Cancelled {
        Failure::Cancelled
    } else {
        Failure::Message(error.to_string())
    }
}

fn input_failure(error: PasswordLoginInputError) -> Failure {
    Failure::Message(error.to_string())
}
