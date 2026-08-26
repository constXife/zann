//! The server connection screen: discover auth methods, authenticate, confirm
//! a changed server fingerprint.

use std::sync::Arc;
use std::time::Duration;

use cosmic::iced::{Length, Subscription, Task};
use cosmic::{theme, widget, Element};
use zann_ui_core::normalize_server_url;

use super::centered;
use crate::backend::off_thread;
use crate::backend::remote::{LoginOutcome, Method, OidcStatus, Remote, ServerProbe};
use crate::i18n::t;

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

#[derive(Clone, Debug)]
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

pub enum Outcome {
    None,
    Task(Task<Message>),
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

pub struct State {
    stage: Stage,
    /// Built on first use, because a purely local vault never needs it.
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
    pub fn stage(&self) -> &Stage {
        &self.stage
    }

    /// The OIDC listener runs on its own thread and has no way to wake the UI,
    /// so the screen polls it while a browser flow is open.
    pub fn subscription(&self) -> Subscription<Message> {
        match self.stage {
            Stage::Oidc | Stage::Fingerprint { .. } => {
                cosmic::iced::time::every(Duration::from_millis(400)).map(|_| Message::Poll)
            }
            _ => Subscription::none(),
        }
    }

    pub fn update(&mut self, message: Message) -> Outcome {
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
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Probed(off_thread(move || remote.probe(url)).await)
                }));
            }

            Message::Probed(Ok(probe)) => {
                self.apply_probe(probe);
                if self.stage == Stage::Oidc {
                    return Outcome::Task(cosmic::task::message(Message::StartOidc));
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
                return Outcome::Task(cosmic::task::future(async move {
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
                return Outcome::Task(cosmic::task::future(async move {
                    Message::OidcStarted(off_thread(move || remote.oidc_begin(url)).await)
                }));
            }

            Message::OidcStarted(Ok(url)) => {
                self.busy = false;
                self.authorization_url = Some(url.clone());
                return Outcome::OpenUrl(url);
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
                return Outcome::Task(cosmic::task::future(async move {
                    Message::FingerprintTrusted(
                        off_thread(move || remote.trust_fingerprint(login_id)).await,
                    )
                }));
            }

            Message::FingerprintTrusted(Ok(())) => {
                self.busy = true;
                return Outcome::Task(cosmic::task::message(Message::Probe));
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
                if let Some(remote) = self.remote.as_ref() {
                    remote.forget_oidc();
                }
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
                if let Some(remote) = self.remote.as_ref() {
                    remote.forget_oidc();
                }
                Outcome::Connected {
                    storage_id,
                    has_personal_keys,
                }
            }
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

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();

        let body = match &self.stage {
            Stage::Server => self.server_form(),
            Stage::Method => self.method_picker(),
            Stage::Password => self.password_form(),
            Stage::Oidc => self.oidc_wait(),
            Stage::Fingerprint { old, new } => self.fingerprint_prompt(old, new),
        };

        let mut column = widget::column::with_capacity(5)
            .push(widget::text::title3(t(match &self.stage {
                Stage::Fingerprint { .. } => "wizard.fingerprintChanged",
                _ => "wizard.connectTitle",
            })))
            .spacing(spacing.space_s)
            .width(Length::Fixed(420.0));

        if let Some(name) = self.server_name.as_ref() {
            column = column.push(widget::text::caption(name.clone()));
        }

        column = column.push(body);

        if let Some(error) = self.error.as_ref() {
            column = column.push(widget::text::caption(error.clone()));
        }

        centered(column.push(widget::button::text(t("wizard.back")).on_press(Message::Cancel)))
    }

    fn server_form(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut submit = widget::button::suggested(t(if self.busy {
            "wizard.checking"
        } else {
            "common.continue"
        }))
        .width(Length::Fill);
        if !self.busy && !self.url.trim().is_empty() {
            submit = submit.on_press(Message::Probe);
        }

        widget::column::with_capacity(2)
            .push(
                widget::text_input::text_input("https://zann.example.com", &self.url)
                    .label(t("auth.serverUrl"))
                    .on_input(Message::UrlInput)
                    .on_submit(|_| Message::Probe),
            )
            .push(submit)
            .spacing(spacing.space_s)
            .into()
    }

    fn method_picker(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(self.methods.len() + 1)
            .push(widget::text::body(t("auth.selectMethod")))
            .spacing(spacing.space_s);

        for method in &self.methods {
            column = column.push(match method {
                Method::Oidc => widget::button::standard(t("auth.oidc"))
                    .width(Length::Fill)
                    .on_press(Message::StartOidc),
                Method::Password => widget::button::standard(t("auth.emailPassword"))
                    .width(Length::Fill)
                    .on_press(Message::ChoosePassword),
            });
        }

        column.into()
    }

    fn password_form(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let ready = !self.busy && !self.email.trim().is_empty() && !self.password.is_empty();
        let label = if self.register {
            "auth.signUp"
        } else {
            "auth.signIn"
        };
        let mut submit = widget::button::suggested(t(if self.busy {
            "wizard.processing"
        } else {
            label
        }))
        .width(Length::Fill);
        if ready {
            submit = submit.on_press(Message::SubmitPassword);
        }

        let mut column = widget::column::with_capacity(4)
            .push(
                widget::text_input::text_input("you@example.com", &self.email)
                    .label(t("auth.email"))
                    .on_input(Message::EmailInput),
            )
            .spacing(spacing.space_s);

        if self.register {
            column = column.push(
                widget::text_input::text_input(t("auth.fullName"), &self.full_name)
                    .label(t("auth.fullName"))
                    .on_input(Message::FullNameInput),
            );
        }

        column
            .push(
                widget::text_input::secure_input(
                    t("auth.password"),
                    &self.password,
                    Some(Message::TogglePassword),
                    self.password_hidden,
                )
                .label(t("auth.password"))
                .on_input(Message::PasswordInput)
                .on_submit(|_| Message::SubmitPassword),
            )
            .push(submit)
            .into()
    }

    fn oidc_wait(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(3).spacing(spacing.space_s);

        match self.authorization_url.as_ref() {
            Some(_) => {
                column = column
                    .push(widget::text::body(t("wizard.oidcHint")))
                    .push(
                        widget::button::link(t("wizard.oidcReopen")).on_press(Message::OpenAuthUrl),
                    )
                    .push(widget::button::text(t("auth.copyLink")).on_press(Message::CopyAuthUrl));
            }
            None => {
                let mut start = widget::button::suggested(t(if self.busy {
                    "wizard.starting"
                } else {
                    "wizard.signInSso"
                }))
                .width(Length::Fill);
                if !self.busy {
                    start = start.on_press(Message::StartOidc);
                }
                column = column.push(start);
            }
        }

        column.into()
    }

    fn fingerprint_prompt<'a>(&'a self, old: &'a str, new: &'a str) -> Element<'a, Message> {
        let spacing = theme::spacing();
        let mut trust =
            widget::button::destructive(t("wizard.trustFingerprint")).width(Length::Fill);
        if !self.busy {
            trust = trust.on_press(Message::TrustFingerprint);
        }

        widget::column::with_capacity(6)
            .push(widget::text::body(t("wizard.fingerprintWarning")))
            .push(widget::text::caption(t("wizard.oldFingerprint")))
            .push(widget::text::monotext(old.to_string()))
            .push(widget::text::caption(t("wizard.newFingerprint")))
            .push(widget::text::monotext(new.to_string()))
            .push(trust)
            .spacing(spacing.space_xxs)
            .into()
    }
}
