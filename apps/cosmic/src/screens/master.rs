//! The master password: create a vault or open an existing one.

use cosmic::iced::{Length, Task};
use cosmic::{theme, widget, Element};

use super::centered;
use crate::backend::local::{self, ItemsPage};
use crate::backend::off_thread;
use crate::i18n::t;
use crate::session::Session;
use zann_ffi::RememberedUnlockFfi;

/// Whether the screen creates a vault or opens one that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    Unlock,
}

pub struct State {
    mode: Mode,
    /// Whether this device can open the vault without the master password, and
    /// with what. Absent until the shell has asked the facade.
    remembered: Option<RememberedUnlockFfi>,
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

#[derive(Clone, Debug)]
pub enum Message {
    /// What this device remembers, answered by the shell on the way in.
    Remembered(RememberedUnlockFfi),
    /// Unlock with the remembered source instead of the password. Waits on a
    /// touch when that source is a hardware key.
    UseRemembered,
    PasswordInput(String),
    ToggleVisibility,
    Submit,
    /// The vault contents, plus a sync error that did not stop it opening.
    Opened(Result<(ItemsPage, Option<String>), String>),
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Opened {
        page: ItemsPage,
        sync_error: Option<String>,
    },
}

impl State {
    pub fn new(mode: Mode, sync_after: Option<String>) -> Self {
        Self {
            mode,
            remembered: None,
            password: String::new(),
            hidden: true,
            busy: false,
            error: None,
            notice: None,
            sync_after,
        }
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

            Message::ToggleVisibility => self.hidden = !self.hidden,

            Message::Submit => {
                if self.busy || self.password.is_empty() {
                    return Outcome::None;
                }
                let facade = session.facade();
                let password = std::mem::take(&mut self.password);
                let storage = self.sync_after.take();
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
                            }
                            // A vault that came from a server starts empty, so
                            // pull it first. A failed sync is worth reporting
                            // but must not keep the vault shut.
                            let sync_error = storage
                                .map(|storage| local::sync(&facade, Some(storage)))
                                .and_then(Result::err);
                            local::items(&facade, None).map(|page| (page, sync_error))
                        })
                        .await,
                    )
                }));
            }

            Message::Opened(Ok((page, sync_error))) => {
                self.busy = false;
                return Outcome::Opened { page, sync_error };
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
        let storage = self.sync_after.take();
        self.busy = true;
        self.error = None;
        Outcome::Task(cosmic::task::future(async move {
            Message::Opened(
                off_thread(move || {
                    local::unlock_remembered(&facade)?;
                    let sync_error = storage
                        .map(|storage| local::sync(&facade, Some(storage)))
                        .and_then(Result::err);
                    local::items(&facade, None).map(|page| (page, sync_error))
                })
                .await,
            )
        }))
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let (title, action) = match self.mode {
            Mode::Create => ("wizard.passwordTitle", "wizard.create"),
            Mode::Unlock => ("unlock.title", "common.unlock"),
        };

        let mut submit = widget::button::suggested(t(if self.busy {
            "wizard.processing"
        } else {
            action
        }))
        .width(Length::Fill);
        if !self.busy && !self.password.is_empty() {
            submit = submit.on_press(Message::Submit);
        }

        let mut form = widget::column::with_capacity(5)
            .push(widget::text::title3(t(title)))
            .push(
                widget::text_input::secure_input(
                    t("wizard.passwordPlaceholder"),
                    &self.password,
                    Some(Message::ToggleVisibility),
                    self.hidden,
                )
                .on_input(Message::PasswordInput)
                .on_submit(|_| Message::Submit),
            )
            .spacing(spacing.space_s)
            .width(Length::Fixed(360.0));

        if self.mode == Mode::Create {
            form = form.push(widget::text::caption(t("wizard.passwordSubtitle")));
        }

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
