//! Connect widgets; lifecycle policy lives in the parent module.

use cosmic::iced::Length;
use cosmic::{theme, widget, Element};

use super::{Event, Message, Method, Stage, State};
use crate::i18n::t;
use crate::screens::centered;

impl State {
    pub fn view(&self) -> Element<'_, Event> {
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

        let generation = self.generation;
        centered(column.push(widget::button::text(t("wizard.back")).on_press(Message::Cancel))).map(
            move |message| Event {
                generation,
                message,
            },
        )
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
