//! Connect widgets; lifecycle policy lives in the parent module.

use cosmic::iced::Length;
use cosmic::{theme, widget, Element};

use super::{Event, Message, Stage, State};
use crate::i18n::t;
use crate::screens::centered;
use zann_core::AuthMethod;

impl State {
    pub fn view(&self) -> Element<'_, Event> {
        let spacing = theme::spacing();

        let body = match &self.flow.snapshot().stage {
            Stage::Server => self.server_form(),
            Stage::Methods => self.method_picker(),
            Stage::Password { .. } => self.password_form(),
            Stage::Browser { .. } => self.oidc_wait(),
            Stage::Complete | Stage::Closed => widget::text::body("").into(),
            Stage::Fingerprint { old, new } => self.fingerprint_prompt(old, new),
        };

        let mut column = widget::column::with_capacity(5)
            .push(widget::text::title3(t(match &self.flow.snapshot().stage {
                Stage::Fingerprint { .. } => "wizard.fingerprintChanged",
                _ => "wizard.connectTitle",
            })))
            .spacing(spacing.space_s)
            .width(Length::Fixed(420.0));

        if let Some(name) = self.flow.snapshot().server_name.as_ref() {
            column = column.push(widget::text::caption(name.clone()));
        }

        column = column.push(body);

        if let Some(error) = self.flow.snapshot().error.as_ref() {
            column = column.push(widget::text::caption(error.clone()));
        }

        let generation = self.generation;
        centered(column.push(widget::button::text(t("wizard.back")).on_press(Message::Back))).map(
            move |message| Event {
                generation,
                message,
            },
        )
    }

    fn server_form(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut submit = widget::button::suggested(t(if self.flow.snapshot().busy {
            "wizard.checking"
        } else {
            "common.continue"
        }))
        .width(Length::Fill);
        if !self.flow.snapshot().busy && !self.url.trim().is_empty() {
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
        let mut column = widget::column::with_capacity(self.flow.snapshot().methods.len() + 1)
            .push(widget::text::body(t("auth.selectMethod")))
            .spacing(spacing.space_s);

        for method in &self.flow.snapshot().methods {
            let button = match method {
                AuthMethod::Oidc => widget::button::standard(t("auth.oidc"))
                    .width(Length::Fill)
                    .on_press(Message::StartOidc),
                AuthMethod::Password => widget::button::standard(t("auth.emailPassword"))
                    .width(Length::Fill)
                    .on_press(Message::ChoosePassword),
                AuthMethod::ServiceAccount => continue,
            };
            column = column.push(button);
        }

        column.into()
    }

    fn password_form(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let ready = self.flow.can_submit_password(&self.email, &self.password);
        let register = matches!(self.stage(), Stage::Password { register: true });
        let label = if register {
            "auth.signUp"
        } else {
            "auth.signIn"
        };
        let mut submit = widget::button::suggested(t(if self.flow.snapshot().busy {
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

        if register {
            column = column.push(
                widget::text_input::text_input(t("auth.fullName"), &self.full_name)
                    .label(t("auth.fullName"))
                    .on_input(Message::FullNameInput),
            );
        }

        let mut column = column
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
            .push(submit);
        if self.flow.snapshot().registration_available {
            column = column.push(
                widget::button::link(t(if register {
                    "auth.haveAccount"
                } else {
                    "auth.noAccount"
                }))
                .on_press(Message::SetRegistering(!register)),
            );
        }
        column.into()
    }

    fn oidc_wait(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(3).spacing(spacing.space_s);

        column = column
            .push(widget::text::body(t("wizard.oidcHint")))
            .push(widget::button::link(t("wizard.oidcReopen")).on_press(Message::OpenAuthUrl))
            .push(widget::button::text(t("auth.copyLink")).on_press(Message::CopyAuthUrl));

        column.into()
    }

    fn fingerprint_prompt<'a>(&'a self, old: &'a str, new: &'a str) -> Element<'a, Message> {
        let spacing = theme::spacing();
        let mut trust =
            widget::button::destructive(t("wizard.trustFingerprint")).width(Length::Fill);
        if !self.flow.snapshot().busy {
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
