//! Local unlock-password form. Validation and key mutation belong to the core.
use super::*;

#[derive(Default)]
pub(super) struct State {
    current: String,
    replacement: String,
    confirmation: String,
    busy: bool,
    notice: Option<String>,
}

#[derive(Clone)]
pub enum Message {
    Current(String),
    Replacement(String),
    Confirmation(String),
    Submit,
    Finished(Result<(), String>),
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordMessage(<redacted>)")
    }
}

impl State {
    pub(super) fn update(&mut self, message: Message, session: &Session) -> Task<Message> {
        match message {
            Message::Current(value) => self.current = value,
            Message::Replacement(value) => self.replacement = value,
            Message::Confirmation(value) => self.confirmation = value,
            Message::Submit if !self.busy && self.can_submit() => {
                let current = std::mem::take(&mut self.current);
                let replacement = std::mem::take(&mut self.replacement);
                self.confirmation.clear();
                self.busy = true;
                self.notice = None;
                let facade = session.facade();
                return cosmic::task::future(async move {
                    Message::Finished(
                        off_thread(move || {
                            facade
                                .change_unlock_password(current, replacement)
                                .map_err(|e| e.to_string())
                        })
                        .await,
                    )
                });
            }
            Message::Finished(result) => {
                self.busy = false;
                self.notice = Some(match result {
                    Ok(()) => t("unlock.passwordChanged"),
                    Err(error) => error,
                });
            }
            Message::Submit => {}
        }
        Task::none()
    }

    fn can_submit(&self) -> bool {
        !self.current.is_empty()
            && !self.replacement.is_empty()
            && self.replacement == self.confirmation
    }

    pub(super) fn view(&self) -> Element<'_, Message> {
        let mut button = widget::button::standard(t("unlock.changePassword"));
        if !self.busy && self.can_submit() {
            button = button.on_press(Message::Submit);
        }
        let mut section = widget::settings::section()
            .title(t("unlock.passwordTitle"))
            .add(
                widget::text_input::secure_input(
                    t("unlock.currentPassword"),
                    &self.current,
                    None::<Message>,
                    true,
                )
                .on_input(Message::Current),
            )
            .add(
                widget::text_input::secure_input(
                    t("unlock.newPassword"),
                    &self.replacement,
                    None::<Message>,
                    true,
                )
                .on_input(Message::Replacement),
            )
            .add(
                widget::text_input::secure_input(
                    t("unlock.confirmPassword"),
                    &self.confirmation,
                    None::<Message>,
                    true,
                )
                .on_input(Message::Confirmation),
            )
            .add(widget::text::caption(t("unlock.changeHelp")))
            .add(button);
        if let Some(notice) = &self.notice {
            section = section.add(widget::text::caption(notice));
        }
        section.into()
    }
}
