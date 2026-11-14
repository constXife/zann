//! The server connection screen: discover auth methods, authenticate, confirm
//! a changed server fingerprint.

use std::sync::Arc;
use std::time::Duration;

use cosmic::iced::{Subscription, Task};
use zann_ui_core::normalize_server_url;

use crate::backend::remote::{LoginOutcome, Method, OidcStatus, Remote, ServerProbe};
use crate::backend::{next_view_request, off_thread};
mod event;
mod view;

pub use event::{Event, Message, Outcome};

#[cfg(test)]
mod tests;

/// Which step of the flow the user is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    /// Asking for the server URL.
    Server,
    /// The server offers more than one method and the user has to pick.
    Method,
    Password,
    /// The browser flow is running.
    Oidc,
    /// The server key changed; the user confirms or aborts.
    Fingerprint {
        old: String,
        new: String,
    },
}

pub struct State {
    generation: u64,
    closed: bool,
    stage: Stage,
    /// Built when the user first connects to a server.
    remote: Option<Arc<Remote>>,
    url: String,
    methods: Vec<Method>,
    /// The server has no internal users yet, so the password form registers.
    register: bool,
    server_name: Option<String>,
    email: String,
    password: String,
    full_name: String,
    password_hidden: bool,
    login_id: String,
    authorization_url: Option<String>,
    busy: bool,
    error: Option<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            generation: next_view_request(),
            closed: false,
            stage: Stage::Server,
            remote: None,
            url: String::new(),
            methods: Vec::new(),
            register: false,
            server_name: None,
            email: String::new(),
            password: String::new(),
            full_name: String::new(),
            password_hidden: true,
            login_id: String::new(),
            authorization_url: None,
            busy: false,
            error: None,
        }
    }
}

impl State {
    /// Starts at the server stage with an address already filled in, as when
    /// reconnecting to a server that was just forgotten.
    pub fn with_server_url(url: String) -> Self {
        let mut state = Self::default();
        state.url = url;
        state
    }

    pub fn server_url(&self) -> &str {
        &self.url
    }

    pub fn stage(&self) -> &Stage {
        &self.stage
    }

    /// The OIDC listener runs on its own thread and has no way to wake the UI,
    /// so the screen polls it while a browser flow is open.
    pub fn subscription(&self) -> Subscription<Event> {
        if self.closed {
            return Subscription::none();
        }
        match self.stage {
            Stage::Oidc | Stage::Fingerprint { .. } => {
                cosmic::iced::time::every(Duration::from_millis(400))
                    .with(self.generation)
                    .map(|(generation, _)| Event {
                        generation,
                        message: Message::Poll,
                    })
            }
            _ => Subscription::none(),
        }
    }

    /// Capture an event while this screen owns the input or task.
    pub fn event(&self, message: Message) -> Event {
        Event {
            generation: self.generation,
            message,
        }
    }

    fn task(&self, task: Task<Message>) -> Outcome {
        let generation = self.generation;
        Outcome::Task(task.map(move |message| Event {
            generation,
            message,
        }))
    }

    pub fn update(&mut self, event: Event) -> Outcome {
        if self.closed || event.generation != self.generation {
            return Outcome::None;
        }
        let message = event.message;
        // Enter/on_submit is delivered even when the corresponding button is disabled.
        if !self.accepts(&message) {
            return Outcome::None;
        }
        match message {
            Message::UrlInput(value) => self.url = value,

            Message::Probe => {
                let url = normalize_server_url(&self.url);
                if url.is_empty() {
                    self.fail("server URL is required".to_string());
                    return Outcome::None;
                }
                self.url = url.clone();
                self.error = None;
                self.busy = true;
                let Some(remote) = self.remote() else {
                    return Outcome::None;
                };
                return self.task(cosmic::task::future(async move {
                    Message::Probed(off_thread(move || remote.probe(url)).await)
                }));
            }

            Message::Probed(Ok(probe)) => {
                self.apply_probe(probe);
                if self.stage == Stage::Oidc {
                    return self.task(cosmic::task::message(Message::StartOidc));
                }
            }

            Message::Probed(Err(err)) => self.fail(err),

            Message::ChoosePassword => self.stage = Stage::Password,

            Message::EmailInput(value) => self.email = value,

            Message::FullNameInput(value) => self.full_name = value,

            Message::PasswordInput(value) => self.password = value,

            Message::TogglePassword => self.password_hidden = !self.password_hidden,

            Message::SubmitPassword => {
                let Some(remote) = self.remote() else {
                    return Outcome::None;
                };
                self.error = None;
                self.busy = true;
                let url = self.url.clone();
                let email = self.email.trim().to_string();
                let password = std::mem::take(&mut self.password);
                let register = self.register;
                let full_name =
                    Some(self.full_name.trim().to_string()).filter(|name| !name.is_empty());
                return self.task(cosmic::task::future(async move {
                    Message::Outcome(
                        off_thread(move || {
                            remote.password_login(url, email, password, full_name, register)
                        })
                        .await,
                    )
                }));
            }

            Message::StartOidc => {
                let Some(remote) = self.remote() else {
                    return Outcome::None;
                };
                self.error = None;
                self.busy = true;
                self.stage = Stage::Oidc;
                let url = self.url.clone();
                return self.task(cosmic::task::future(async move {
                    Message::OidcStarted(off_thread(move || remote.oidc_begin(url)).await)
                }));
            }

            Message::OidcStarted(Ok(url)) => {
                self.busy = false;
                self.authorization_url = Some(url);
                return self.task(cosmic::task::message(Message::OpenAuthUrl));
            }

            Message::OidcStarted(Err(err)) => self.fail(err),

            Message::OpenAuthUrl => {
                if let Some(url) = self.authorization_url.clone() {
                    return Outcome::OpenUrl(url);
                }
            }

            Message::CopyAuthUrl => {
                if let Some(url) = self.authorization_url.clone() {
                    return Outcome::Copy(url);
                }
            }

            Message::TrustFingerprint => {
                let Some(remote) = self.remote() else {
                    return Outcome::None;
                };
                let login_id = self.login_id.clone();
                self.busy = true;
                self.error = None;
                return self.task(cosmic::task::future(async move {
                    Message::FingerprintTrusted(
                        off_thread(move || remote.trust_fingerprint(login_id)).await,
                    )
                }));
            }

            Message::FingerprintTrusted(Ok(())) => {
                self.busy = false;
                self.stage = Stage::Server;
                return self.task(cosmic::task::message(Message::Probe));
            }

            Message::FingerprintTrusted(Err(err)) => self.fail(err),

            Message::Outcome(Ok(outcome)) => return self.apply_outcome(outcome),

            Message::Outcome(Err(err)) => self.fail(err),

            Message::Poll => {
                let Some(remote) = self.remote.clone() else {
                    return Outcome::None;
                };
                for status in remote.poll_oidc() {
                    match status {
                        OidcStatus::Pending => self.busy = false,
                        OidcStatus::Success {
                            storage_id,
                            has_personal_keys,
                        } => {
                            return self.apply_outcome(LoginOutcome::Success {
                                storage_id,
                                has_personal_keys,
                            })
                        }
                        OidcStatus::FingerprintChanged { login_id, old, new } => {
                            return self.apply_outcome(LoginOutcome::FingerprintChanged {
                                login_id,
                                old,
                                new,
                            })
                        }
                        OidcStatus::Failed(message) => self.fail(message),
                    }
                }
            }

            Message::Cancel => {
                self.close();
                return Outcome::Cancelled;
            }
        }
        Outcome::None
    }

    /// Moves on once the server has told us what it supports; a server with a
    /// single method skips the picker.
    fn apply_probe(&mut self, probe: ServerProbe) {
        let fingerprint_changed = probe.fingerprint_changed.clone();
        self.register = probe.register;
        self.server_name = probe.server_name;
        self.methods = probe.methods;
        self.busy = false;
        self.stage = if let Some((old, new)) = fingerprint_changed {
            self.login_id = "connection".to_string();
            Stage::Fingerprint { old, new }
        } else {
            match self.methods.as_slice() {
                [Method::Password] => Stage::Password,
                [Method::Oidc] => Stage::Oidc,
                _ => Stage::Method,
            }
        };
    }

    fn apply_outcome(&mut self, outcome: LoginOutcome) -> Outcome {
        match outcome {
            LoginOutcome::Pending => {
                self.busy = false;
                self.stage = Stage::Oidc;
                Outcome::None
            }
            LoginOutcome::FingerprintChanged { login_id, old, new } => {
                self.busy = false;
                self.login_id = login_id;
                self.stage = Stage::Fingerprint { old, new };
                Outcome::None
            }
            LoginOutcome::Success {
                storage_id,
                has_personal_keys,
            } => {
                self.close();
                Outcome::Connected {
                    storage_id,
                    has_personal_keys,
                }
            }
        }
    }

    fn accepts(&self, message: &Message) -> bool {
        match message {
            Message::Probe => !self.busy && self.stage == Stage::Server,
            Message::SubmitPassword => {
                !self.busy
                    && self.stage == Stage::Password
                    && !self.email.trim().is_empty()
                    && !self.password.is_empty()
            }
            Message::StartOidc => {
                !self.busy
                    && matches!(self.stage, Stage::Method | Stage::Oidc)
                    && self.authorization_url.is_none()
            }
            Message::TrustFingerprint => {
                !self.busy && matches!(self.stage, Stage::Fingerprint { .. })
            }
            Message::ChoosePassword => !self.busy && self.stage == Stage::Method,
            Message::UrlInput(_) => !self.busy && self.stage == Stage::Server,
            Message::EmailInput(_) | Message::FullNameInput(_) | Message::PasswordInput(_) => {
                !self.busy && self.stage == Stage::Password
            }
            _ => true,
        }
    }

    fn close(&mut self) {
        self.closed = true;
        self.password.clear();
        self.authorization_url = None;
        if let Some(remote) = &self.remote {
            remote.cancel();
        }
    }

    fn remote(&mut self) -> Option<Arc<Remote>> {
        if self.remote.is_none() {
            match Remote::new() {
                Ok(remote) => self.remote = Some(Arc::new(remote)),
                Err(err) => {
                    self.fail(err);
                    return None;
                }
            }
        }
        self.remote.clone()
    }

    fn fail(&mut self, error: String) {
        self.busy = false;
        self.error = Some(error);
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.close();
    }
}
