//! Security settings: how this device remembers the unlock.
//!
//! Only one source is ever active. Enrolling a key switches to it, and removing
//! the last key switches back — that rule lives in `zann-keystore`, so this
//! screen shows the result rather than deciding it.

use cosmic::iced::{Alignment, Length, Task};
use cosmic::{theme, widget, Element};
use zann_ffi::RememberedUnlockFfi;

use crate::backend::local;
use crate::backend::off_thread;
use crate::session::Session;

pub struct State {
    remembered: Option<RememberedUnlockFfi>,
    /// Set while an authenticator is being waited on, so the view can say what
    /// the user is supposed to do with it.
    enrolling: bool,
    busy: bool,
    error: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Message {
    Loaded(Result<RememberedUnlockFfi, String>),
    Enroll,
    Remove(String),
    UseKeystore,
    Forget,
    Close,
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Close,
}

impl State {
    pub fn new() -> Self {
        Self {
            remembered: None,
            enrolling: false,
            busy: false,
            error: None,
        }
    }

    /// Loading is a plain file read, but it goes through the same worker thread
    /// as everything else so the facade is only touched from one place.
    pub fn load(session: &Session) -> Task<Message> {
        let facade = session.facade();
        cosmic::task::future(async move {
            Message::Loaded(off_thread(move || local::remembered_unlock(&facade)).await)
        })
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::Loaded(Ok(remembered)) => {
                self.busy = false;
                self.enrolling = false;
                self.remembered = Some(remembered);
            }

            Message::Loaded(Err(err)) => {
                self.busy = false;
                self.enrolling = false;
                self.error = Some(err);
            }

            Message::Enroll => {
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.enrolling = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || {
                            local::enroll_hardware_key(&facade, String::new())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::Remove(credential_id) => {
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || {
                            local::remove_hardware_key(&facade, credential_id)?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::UseKeystore => {
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || {
                            facade
                                .remember_with_keystore()
                                .map_err(|err| err.to_string())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::Forget => {
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || {
                            facade.forget_remembered().map_err(|err| err.to_string())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::Close => return Outcome::Close,
        }
        Outcome::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(8)
            .push(widget::text::title3("Unlock on this device"))
            .spacing(spacing.space_s)
            .width(Length::Fixed(460.0));

        let Some(remembered) = self.remembered.as_ref() else {
            return super::centered(column.push(widget::text::body("Loading…")));
        };

        column = column.push(widget::text::body(match remembered.source.as_str() {
            "hardware_key" => "Unlocking with a hardware key.",
            _ if remembered.armed => "Unlocking with the system keystore.",
            _ => "This device asks for the master password every time.",
        }));

        if remembered.hardware_supported {
            for key in &remembered.hardware_keys {
                column = column.push(
                    widget::row::with_capacity(2)
                        .push(
                            widget::text::body(format!("{} · {}", key.label, key.enrolled_at))
                                .width(Length::Fill),
                        )
                        .push(
                            widget::button::text("Remove")
                                .on_press(Message::Remove(key.credential_id.clone())),
                        )
                        .align_y(Alignment::Center),
                );
            }

            let mut enroll = widget::button::standard(if self.enrolling {
                "Insert the key and touch it…"
            } else if remembered.hardware_keys.is_empty() {
                "Enrol a hardware key"
            } else {
                "Enrol another key"
            });
            if !self.busy {
                enroll = enroll.on_press(Message::Enroll);
            }
            column = column.push(enroll);

            // Asked once, in the flow, because nobody goes looking for this.
            if remembered.hardware_keys.len() == 1 {
                column = column.push(widget::text::caption(
                    "Add a backup key: if the only one is lost, unlocking falls back to the master password.",
                ));
            }
        } else {
            column = column.push(widget::text::caption(
                "Hardware keys are not supported on this platform yet.",
            ));
        }

        column = if remembered.armed {
            column.push(
                widget::button::text("Ask for the master password every time")
                    .on_press(Message::Forget),
            )
        } else {
            column.push(
                widget::button::text("Remember with the system keystore")
                    .on_press(Message::UseKeystore),
            )
        };

        if let Some(error) = self.error.as_ref() {
            column = column.push(widget::text::caption(error.clone()));
        }

        super::centered(column.push(widget::button::standard("Back").on_press(Message::Close)))
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
