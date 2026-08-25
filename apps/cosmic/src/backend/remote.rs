//! Logging in against a Zann server through the canonical application client.

use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use zann_client::app::{
    AppClient, ClientId, ConnectionTrustChallenge, LoginPassword, PasswordLoginRequest,
    PasswordRegistrationRequest, PrepareConnectionOutcome, PreparedConnection,
    SessionCancellationHandle, SessionClient, SessionOperation,
};
use zann_client::credentials::{OsCredentialStore, OsLegacyCredentialSource};
use zann_client::oidc::OidcBrowserErrorKind;
use zann_client_sqlite::SqliteSyncStoreFactory;
use zann_core::AuthMethod;
use zann_db::{connect_sqlite_file_with_max, migrate_local};

use super::active_database_location;

const PROFILE: &str = "default";
const CONNECTION_NAME: &str = "Remote";
const LOGIN_DEADLINE: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Oidc,
    Password,
}

#[derive(Debug, Clone)]
pub struct ServerProbe {
    pub methods: Vec<Method>,
    pub register: bool,
    pub server_name: Option<String>,
    pub fingerprint_changed: Option<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum LoginOutcome {
    Success {
        storage_id: String,
        has_personal_keys: bool,
    },
    FingerprintChanged {
        login_id: String,
        old: String,
        new: String,
    },
    Pending,
}

#[derive(Debug, Clone)]
pub enum OidcStatus {
    Pending,
    Success {
        storage_id: String,
        has_personal_keys: bool,
    },
    FingerprintChanged {
        login_id: String,
        old: String,
        new: String,
    },
    Failed(String),
}

pub struct Remote {
    runtime: Runtime,
    client: Arc<AppClient>,
    prepared: Mutex<Option<PreparedConnection>>,
    trust: Mutex<Option<ConnectionTrustChallenge>>,
    oidc_rx: Mutex<Option<Receiver<OidcStatus>>>,
    oidc_cancel: Mutex<Option<SessionCancellationHandle>>,
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
        let pool = runtime
            .block_on(connect_sqlite_file_with_max(location.file_location(), 5))
            .map_err(|err| err.to_string())?;
        runtime
            .block_on(migrate_local(&pool))
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
            prepared: Mutex::new(None),
            trust: Mutex::new(None),
            oidc_rx: Mutex::new(None),
            oidc_cancel: Mutex::new(None),
        })
    }

    pub fn probe(&self, server_url: String) -> Result<ServerProbe, String> {
        let outcome = self
            .runtime
            .block_on(
                self.client
                    .prepare_connection(&server_url, CONNECTION_NAME, PROFILE),
            )
            .map_err(|error| error.to_string())?;
        let (prepared, fingerprint_changed) = match outcome {
            PrepareConnectionOutcome::Ready(prepared) => {
                *self.prepared.lock().expect("lock poisoned") = Some(prepared.clone());
                *self.trust.lock().expect("lock poisoned") = None;
                (prepared, None)
            }
            PrepareConnectionOutcome::FingerprintChanged(challenge) => {
                let prepared = challenge.prepared().clone();
                let changed = Some((
                    challenge.old_fingerprint().to_string(),
                    challenge.new_fingerprint().to_string(),
                ));
                *self.prepared.lock().expect("lock poisoned") = None;
                *self.trust.lock().expect("lock poisoned") = Some(*challenge);
                (prepared, changed)
            }
        };
        let methods = prepared
            .auth_methods()
            .iter()
            .filter_map(|method| match method {
                AuthMethod::Oidc => Some(Method::Oidc),
                AuthMethod::Password => Some(Method::Password),
                _ => None,
            })
            .collect::<Vec<_>>();
        if methods.is_empty() {
            return Err("server offers no interactive auth methods".to_string());
        }
        Ok(ServerProbe {
            methods,
            register: prepared.registration_available(),
            server_name: prepared.server_name().map(str::to_string),
            fingerprint_changed,
        })
    }

    pub fn password_login(
        &self,
        _server_url: String,
        email: String,
        password: String,
        full_name: Option<String>,
        register: bool,
    ) -> Result<LoginOutcome, String> {
        let prepared = self
            .prepared
            .lock()
            .expect("lock poisoned")
            .clone()
            .ok_or_else(|| "server connection has not been prepared".to_string())?;
        let password = LoginPassword::new(password).map_err(|error| error.to_string())?;
        let (operation, _) = SessionOperation::new(Instant::now() + LOGIN_DEADLINE);
        let access = if register {
            let request = PasswordRegistrationRequest::new(
                prepared.target().clone(),
                email,
                password,
                full_name,
            )
            .map_err(|error| error.to_string())?;
            self.runtime
                .block_on(self.client.password_register(request, operation))
        } else {
            let request = PasswordLoginRequest::new(prepared.target().clone(), email, password)
                .map_err(|error| error.to_string())?;
            self.runtime
                .block_on(self.client.password_login(request, operation))
        }
        .map_err(|error| error.to_string())?;
        let status = self
            .runtime
            .block_on(self.client.personal_vault_status(&access))
            .map_err(|error| error.to_string())?;
        Ok(LoginOutcome::Success {
            storage_id: prepared.storage_id().to_string(),
            has_personal_keys: status.personal_key_envelopes_present(),
        })
    }

    pub fn oidc_begin(&self, _server_url: String) -> Result<String, String> {
        let prepared = self
            .prepared
            .lock()
            .expect("lock poisoned")
            .clone()
            .ok_or_else(|| "server connection has not been prepared".to_string())?;
        let (operation, cancellation) = SessionOperation::new(Instant::now() + LOGIN_DEADLINE);
        let login = self
            .runtime
            .block_on(
                self.client
                    .begin_oidc_login(prepared.target().clone(), operation),
            )
            .map_err(|error| error.to_string())?;
        let authorization_url = login.authorization_url().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let client = Arc::clone(&self.client);
        let storage_id = prepared.storage_id().to_string();
        self.runtime.handle().spawn(async move {
            let status = match login.finish(&client).await {
                Ok(access) => match client.personal_vault_status(&access).await {
                    Ok(status) => OidcStatus::Success {
                        storage_id,
                        has_personal_keys: status.personal_key_envelopes_present(),
                    },
                    Err(error) => OidcStatus::Failed(error.to_string()),
                },
                Err(error) => {
                    let message = match error.kind() {
                        OidcBrowserErrorKind::Cancelled => "OIDC login was cancelled".to_string(),
                        _ => error.to_string(),
                    };
                    OidcStatus::Failed(message)
                }
            };
            let _ = tx.send(status);
        });
        *self.oidc_rx.lock().expect("lock poisoned") = Some(rx);
        *self.oidc_cancel.lock().expect("lock poisoned") = Some(cancellation);
        Ok(authorization_url)
    }

    pub fn trust_fingerprint(&self, _login_id: String) -> Result<(), String> {
        let challenge = self
            .trust
            .lock()
            .expect("lock poisoned")
            .take()
            .ok_or_else(|| "fingerprint challenge is no longer current".to_string())?;
        let prepared = self
            .client
            .trust_connection(challenge)
            .map_err(|error| error.to_string())?;
        *self.prepared.lock().expect("lock poisoned") = Some(prepared);
        Ok(())
    }

    pub fn poll_oidc(&self) -> Vec<OidcStatus> {
        let guard = self.oidc_rx.lock().expect("lock poisoned");
        let Some(rx) = guard.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while let Ok(status) = rx.try_recv() {
            out.push(status);
        }
        out
    }

    pub fn forget_oidc(&self) {
        if let Some(cancellation) = self.oidc_cancel.lock().expect("lock poisoned").take() {
            cancellation.cancel();
        }
        *self.oidc_rx.lock().expect("lock poisoned") = None;
    }
}
