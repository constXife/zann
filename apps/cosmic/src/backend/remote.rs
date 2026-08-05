//! Logging in against a zann server, through `zann-client`.

use std::sync::mpsc::Receiver;
use std::sync::Mutex;

use tokio::runtime::Runtime;
use zann_client::types::OidcLoginStatusResponse;
use zann_client::ClientState;
use zann_core::AuthMethod;
use zann_db::{connect_sqlite_with_max, migrate_local};

use super::{client_root, default_db_url};

/// Which interactive auth methods a server offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Oidc,
    Password,
}

#[derive(Debug, Clone)]
pub struct ServerProbe {
    pub methods: Vec<Method>,
    /// A server with no internal users yet expects the first login to register.
    pub register: bool,
    pub server_name: Option<String>,
}

/// What a login attempt produced. Errors travel as `Err`.
#[derive(Debug, Clone)]
pub enum LoginOutcome {
    Success {
        storage_id: String,
        has_personal_keys: bool,
    },
    /// The server key changed since the last login; the user has to confirm.
    FingerprintChanged {
        login_id: String,
        old: String,
        new: String,
    },
    /// OIDC only: the browser flow is running, statuses arrive through
    /// [`Remote::poll_oidc`].
    Pending,
}

/// A status update from the OIDC callback listener, flattened for the UI.
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

/// The server-facing half of the app: its own runtime, the client state that
/// holds pending logins, and the channel the OIDC listener thread reports on.
pub struct Remote {
    runtime: Runtime,
    state: ClientState,
    oidc_rx: Mutex<Option<Receiver<OidcLoginStatusResponse>>>,
}

impl Remote {
    pub fn new() -> Result<Self, String> {
        let db_url = default_db_url();
        let _ = std::fs::create_dir_all(client_root(&db_url));
        let runtime = Runtime::new().map_err(|err| err.to_string())?;
        let pool = runtime
            .block_on(connect_sqlite_with_max(&db_url, 5))
            .map_err(|err| err.to_string())?;
        runtime
            .block_on(migrate_local(&pool))
            .map_err(|err| err.to_string())?;
        let state = ClientState::new(pool, client_root(&db_url));
        Ok(Self {
            runtime,
            state,
            oidc_rx: Mutex::new(None),
        })
    }

    /// Asks the server which auth methods it offers before showing any form.
    pub fn probe(&self, server_url: String) -> Result<ServerProbe, String> {
        let client = reqwest::Client::new();
        let info = self
            .runtime
            .block_on(zann_client::remote::fetch_system_info(&client, &server_url))?;
        let mut methods = Vec::new();
        for method in &info.auth_methods {
            match AuthMethod::try_from(*method) {
                Ok(AuthMethod::Oidc) => methods.push(Method::Oidc),
                Ok(AuthMethod::Password) => methods.push(Method::Password),
                _ => {}
            }
        }
        if methods.is_empty() {
            return Err("server offers no interactive auth methods".to_string());
        }
        Ok(ServerProbe {
            methods,
            register: info.internal_users_present == Some(false),
            server_name: info.server_name.clone(),
        })
    }

    pub fn password_login(
        &self,
        server_url: String,
        email: String,
        password: String,
        full_name: Option<String>,
        register: bool,
    ) -> Result<LoginOutcome, String> {
        let response = if register {
            self.runtime
                .block_on(zann_client::auth_password::password_register(
                    server_url,
                    email,
                    password,
                    full_name,
                    &self.state,
                ))?
        } else {
            self.runtime
                .block_on(zann_client::auth_password::password_login(
                    server_url,
                    email,
                    password,
                    &self.state,
                ))?
        };

        let data = match (response.ok, response.data) {
            (true, Some(data)) => data,
            _ => {
                return Err(response
                    .error
                    .map(|err| err.message)
                    .unwrap_or_else(|| "authentication failed".to_string()))
            }
        };

        match data.status.as_str() {
            "success" => Ok(LoginOutcome::Success {
                storage_id: data.storage_id.unwrap_or_default(),
                has_personal_keys: data.personal_key_envelopes_present.unwrap_or(false),
            }),
            "fingerprint_changed" => Ok(LoginOutcome::FingerprintChanged {
                login_id: data.login_id.unwrap_or_default(),
                old: data.old_fingerprint.unwrap_or_default(),
                new: data.new_fingerprint.unwrap_or_default(),
            }),
            other => Err(format!("unexpected login status: {other}")),
        }
    }

    /// Starts the browser flow and returns the URL to open. Progress arrives
    /// through [`Self::poll_oidc`].
    pub fn oidc_begin(&self, server_url: String) -> Result<String, String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let response = self.runtime.block_on(zann_client::auth_oidc::begin_login(
            server_url,
            &self.state,
            tx,
        ))?;
        match (response.ok, response.data) {
            (true, Some(data)) => {
                *self.oidc_rx.lock().expect("lock poisoned") = Some(rx);
                Ok(data.authorization_url)
            }
            _ => Err(response
                .error
                .map(|err| err.message)
                .unwrap_or_else(|| "could not start the OIDC login".to_string())),
        }
    }

    /// Accepts a changed server fingerprint and resumes the login.
    pub fn trust_fingerprint(&self, login_id: String) -> Result<(), String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let response = self
            .runtime
            .block_on(zann_client::auth_oidc::trust_fingerprint(
                login_id,
                &self.state,
                tx,
            ))?;
        if !response.ok {
            return Err(response
                .error
                .map(|err| err.message)
                .unwrap_or_else(|| "could not trust the fingerprint".to_string()));
        }
        *self.oidc_rx.lock().expect("lock poisoned") = Some(rx);
        Ok(())
    }

    /// Drains whatever the listener thread has reported so far. Never blocks.
    pub fn poll_oidc(&self) -> Vec<OidcStatus> {
        let guard = self.oidc_rx.lock().expect("lock poisoned");
        let Some(rx) = guard.as_ref() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while let Ok(payload) = rx.try_recv() {
            out.push(match payload.status.as_str() {
                "success" => OidcStatus::Success {
                    storage_id: payload.storage_id.unwrap_or_default(),
                    has_personal_keys: payload.personal_key_envelopes_present.unwrap_or(false),
                },
                "fingerprint_changed" => OidcStatus::FingerprintChanged {
                    login_id: payload.login_id,
                    old: payload.old_fingerprint.unwrap_or_default(),
                    new: payload.new_fingerprint.unwrap_or_default(),
                },
                "pending" => OidcStatus::Pending,
                _ => OidcStatus::Failed(
                    payload
                        .message
                        .unwrap_or_else(|| "authentication failed".to_string()),
                ),
            });
        }
        out
    }

    pub fn forget_oidc(&self) {
        *self.oidc_rx.lock().expect("lock poisoned") = None;
    }
}
