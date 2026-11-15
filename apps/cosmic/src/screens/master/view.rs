use super::*;
use crate::screens::centered;
use cosmic::iced::Length;
use cosmic::{theme, widget, Element};

impl State {
    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let title = self.mode.title_key();
        let action = if self.creating() {
            "wizard.create"
        } else {
            "common.unlock"
        };

        let mut submit = widget::button::suggested(t(if self.busy {
            "wizard.processing"
        } else {
            action
        }))
        .width(Length::Fill);
        if self.can_submit() {
            submit = submit.on_press(Message::Submit);
        }

        let mut form = widget::column::with_capacity(5)
            .push(widget::text::title3(t(title)))
            .push(
                widget::text_input::secure_input(
                    t(self.mode.placeholder_key()),
                    &self.password,
                    Some(Message::ToggleVisibility),
                    self.hidden,
                )
                .id(self.password_id.clone())
                .on_input(Message::PasswordInput)
                .on_submit(|_| Message::PasswordSubmitted),
            )
            .spacing(spacing.space_s)
            .width(Length::Fixed(360.0));

        if self.creating() {
            form = form.push(
                widget::text_input::secure_input(
                    t(self.mode.confirmation_key()),
                    &self.confirmation,
                    Some(Message::ToggleVisibility),
                    self.hidden,
                )
                .id(self.confirmation_id.clone())
                .on_input(Message::ConfirmationInput)
                .on_submit(|_| Message::Submit),
            );
            form = form.push(
                widget::text::caption(if self.passwords_mismatch() {
                    t("wizard.passwordMismatch")
                } else {
                    String::new()
                })
                .height(20),
            );
        }
        form = form.push(widget::text::caption(t(self.mode.help_key())));
        if let Some(label) = &self.account_label {
            form = form.push(widget::text::caption(label.clone()));
        }
        if self.creating() {
            let feedback = zann_ui_core::password::password_feedback(&self.password);
            if let Some(key) = feedback.strength_key {
                form = form.push(widget::text::caption(t(key)));
            }
            if let Some(key) = feedback.validation_key {
                form = form.push(widget::text::caption(t(key)));
            }
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

        let mut recovery = widget::button::standard(t("recovery.title"));
        if !self.busy {
            recovery = recovery.on_press(Message::Recovery);
        }
        centered(form.push(submit).push(recovery))
    }
}
