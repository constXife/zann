//! The master password: create a vault or open an existing one.

use cosmic::iced::{Length, Task};
use cosmic::{theme, widget, Element};

use super::centered;
use crate::backend::local::{self, ItemsPage};
use crate::backend::off_thread;
use crate::session::Session;

/// Whether the screen creates a vault or opens one that already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Create,
    Unlock,
}

pub struct State {
    mode: Mode,
    password: String,
    hidden: bool,
    busy: bool,
    error: Option<String>,
    /// Set after a server login: the storage to pull once the vault is open.
    sync_after: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Message {
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
            password: String::new(),
            hidden: true,
            busy: false,
            error: None,
            sync_after,
        }
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
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

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let (title, action) = match self.mode {
            Mode::Create => ("Choose a master password", "Create the vault"),
            Mode::Unlock => ("Unlock your vault", "Unlock"),
        };

        let mut submit = widget::button::suggested(if self.busy { "Working…" } else { action })
            .width(Length::Fill);
        if !self.busy && !self.password.is_empty() {
            submit = submit.on_press(Message::Submit);
        }

        let mut form = widget::column::with_capacity(5)
            .push(widget::text::title3(title))
            .push(
                widget::text_input::secure_input(
                    "Master password",
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
            form = form.push(widget::text::caption(
                "At least 8 characters. It is never sent to the server.",
            ));
        }

        if self.sync_after.is_some() {
            form = form.push(widget::text::caption(
                "The vault will sync with the server right after this.",
            ));
        }

        if let Some(error) = self.error.as_ref() {
            form = form.push(widget::text::caption(error.clone()));
        }

        centered(form.push(submit))
    }
}
