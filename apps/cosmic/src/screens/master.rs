//! The master password: create a vault or open an existing one.

use cosmic::iced::{Length, Task};
use cosmic::{theme, widget, Element};

use super::centered;
use crate::backend::local::{self, ItemsPage};
use crate::backend::off_thread;
use crate::i18n::t;
use crate::session::Session;
use zann_client::app::local::RememberedUnlock;

/// Whether the screen creates a vault or opens one that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    Unlock,
    AccountCreate,
    AccountUnlock,
}

pub struct State {
    mode: Mode,
    account_mode: Option<Mode>,
    confirmation: String,
    /// Whether this device can open the vault without the master password, and
    /// with what. Absent until the shell has asked the facade.
    remembered: Option<RememberedUnlock>,
    password: String,
    hidden: bool,
    busy: bool,
    error: Option<String>,
    /// Something that happened before this screen appeared and the user needs
    /// to know about — a snapshot restore, above all, which can change which
    /// password opens the vault.
    notice: Option<String>,
    /// Set after a server login: the storage to pull once the vault is open.
    sync_after: Option<String>,
}

#[derive(Clone)]
pub enum OpenResult {
    AccountKeyRequired,
    Vault {
        page: ItemsPage,
        synced: Option<Result<(), String>>,
    },
}

#[derive(Clone)]
pub enum Message {
    /// What this device remembers, answered by the shell on the way in.
    Remembered(RememberedUnlock),
    /// Unlock with the remembered source instead of the password. Waits on a
    /// touch when that source is a hardware key.
    UseRemembered,
    PasswordInput(String),
    ConfirmationInput(String),
    ToggleVisibility,
    Submit,
    /// The vault contents, plus the outcome of the sync that ran on the way
    /// in, if one did; a failed one did not stop the vault opening.
    Opened(Result<OpenResult, String>),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterMessage(<redacted>)")
    }
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Opened {
        page: ItemsPage,
        synced: Option<Result<(), String>>,
    },
}

impl State {
    pub fn new(mode: Mode, sync_after: Option<String>) -> Self {
        Self {
            mode,
            account_mode: None,
            confirmation: String::new(),
            remembered: None,
            password: String::new(),
            hidden: true,
            busy: false,
            error: None,
            notice: None,
            sync_after,
        }
    }

    pub fn with_account(mut self, has_keys: bool) -> Self {
        self.account_mode = Some(if has_keys {
            Mode::AccountUnlock
        } else {
            Mode::AccountCreate
        });
        self
    }

    fn creating(&self) -> bool {
        matches!(self.mode, Mode::Create | Mode::AccountCreate)
    }

    /// Carry a message onto the unlock screen from whatever sent the user back
    /// to it.
    pub fn with_notice(mut self, notice: String) -> Self {
        self.notice = Some(notice);
        self
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::Remembered(remembered) => {
                let armed = remembered.armed;
                self.remembered = Some(remembered);
                // A key already in the port should not need a click as well.
                if armed && self.mode == Mode::Unlock && !self.busy {
                    return self.unlock_remembered(session);
                }
            }

            Message::UseRemembered => return self.unlock_remembered(session),

            Message::PasswordInput(value) => self.password = value,
            Message::ConfirmationInput(value) => self.confirmation = value,

            Message::ToggleVisibility => self.hidden = !self.hidden,

            Message::Submit => {
                if self.busy
                    || self.password.is_empty()
                    || (self.creating() && self.password != self.confirmation)
                {
                    return Outcome::None;
                }
                let facade = session.facade();
                let password = std::mem::take(&mut self.password);
                self.confirmation.clear();
                let storage = self.sync_after.clone();
                let mode = self.mode;
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Opened(
                        off_thread(move || {
                            match mode {
                                Mode::Create => {
                                    local::initialize_master_password(&facade, password)?
                                }
                                Mode::Unlock => local::unlock(&facade, password)?,
                                Mode::AccountCreate | Mode::AccountUnlock => {
                                    facade
                                        .enroll_account_key(password)
                                        .map_err(|e| e.to_string())?;
                                }
                            }
                            if storage.is_some()
                                && matches!(mode, Mode::Create | Mode::Unlock)
                                && !facade
                                    .activate_connected_account()
                                    .map_err(|e| e.to_string())?
                            {
                                return Ok(OpenResult::AccountKeyRequired);
                            }
                            // A vault that came from a server starts empty, so
                            // pull it first. A failed sync is worth reporting
                            // but must not keep the vault shut.
                            let synced =
                                storage.map(|storage| local::sync_new_server(&facade, storage));
                            local::items(&facade, None, None)
                                .map(|page| OpenResult::Vault { page, synced })
                        })
                        .await,
                    )
                }));
            }

            Message::Opened(Ok(OpenResult::Vault { page, synced })) => {
                self.busy = false;
                self.sync_after = None;
                return Outcome::Opened { page, synced };
            }

            Message::Opened(Ok(OpenResult::AccountKeyRequired)) => {
                self.busy = false;
                if let Some(mode) = self.account_mode {
                    self.mode = mode;
                }
            }

            Message::Opened(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }
        }
        Outcome::None
    }

    /// Open the vault with whatever this device remembers. Blocks the worker
    /// thread on a touch when the source is a hardware key, which is why the
    /// screen reports itself busy for the whole call.
    fn unlock_remembered(&mut self, session: &Session) -> Outcome {
        if self.busy {
            return Outcome::None;
        }
        let facade = session.facade();
        let storage = self.sync_after.clone();
        self.busy = true;
        self.error = None;
        Outcome::Task(cosmic::task::future(async move {
            Message::Opened(
                off_thread(move || {
                    local::unlock_remembered(&facade)?;
                    if storage.is_some()
                        && !facade
                            .activate_connected_account()
                            .map_err(|e| e.to_string())?
                    {
                        return Ok(OpenResult::AccountKeyRequired);
                    }
                    let synced = storage.map(|storage| local::sync_new_server(&facade, storage));
                    local::items(&facade, None, None).map(|page| OpenResult::Vault { page, synced })
                })
                .await,
            )
        }))
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let (title, action) = match self.mode {
            Mode::Create => ("unlock.createTitle", "wizard.create"),
            Mode::AccountCreate => ("unlock.accountCreateTitle", "wizard.create"),
            Mode::AccountUnlock => ("unlock.accountTitle", "common.unlock"),
            Mode::Unlock => ("unlock.title", "common.unlock"),
        };

        let mut submit = widget::button::suggested(t(if self.busy {
            "wizard.processing"
        } else {
            action
        }))
        .width(Length::Fill);
        if !self.busy
            && !self.password.is_empty()
            && (!self.creating() || self.password == self.confirmation)
        {
            submit = submit.on_press(Message::Submit);
        }

        let mut form = widget::column::with_capacity(5)
            .push(widget::text::title3(t(title)))
            .push(
                widget::text_input::secure_input(
                    t(
                        if matches!(self.mode, Mode::AccountCreate | Mode::AccountUnlock) {
                            "unlock.accountPlaceholder"
                        } else {
                            "unlock.passwordPlaceholder"
                        },
                    ),
                    &self.password,
                    Some(Message::ToggleVisibility),
                    self.hidden,
                )
                .on_input(Message::PasswordInput)
                .on_submit(|_| Message::Submit),
            )
            .spacing(spacing.space_s)
            .width(Length::Fixed(360.0));

        if self.creating() {
            form = form.push(
                widget::text_input::secure_input(
                    t("unlock.confirmPassword"),
                    &self.confirmation,
                    None::<Message>,
                    true,
                )
                .on_input(Message::ConfirmationInput)
                .on_submit(|_| Message::Submit),
            );
        }
        form = form.push(widget::text::caption(t(
            if matches!(self.mode, Mode::AccountCreate | Mode::AccountUnlock) {
                "unlock.accountHelp"
            } else {
                "unlock.deviceHelp"
            },
        )));

        if self.sync_after.is_some() {
            form = form.push(widget::text::caption(t("wizard.syncAfterUnlock")));
        }

        if let Some(notice) = self.notice.as_ref() {
            form = form.push(widget::text::body(notice.clone()));
        }

        if let Some(error) = self.error.as_ref() {
            form = form.push(widget::text::caption(error.clone()));
        }

        if self.remembered.as_ref().is_some_and(|state| state.armed) && self.mode == Mode::Unlock {
            let label = if self.busy {
                t("unlock.hardwareKeyTouch")
            } else {
                t("unlock.savedUnlock")
            };
            let mut retry = widget::button::standard(label).width(Length::Fill);
            if !self.busy {
                retry = retry.on_press(Message::UseRemembered);
            }
            form = form.push(retry);
        }

        centered(form.push(submit))
    }
}
