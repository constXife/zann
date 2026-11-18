//! Account security widgets over canonical metadata.
use super::*;
impl State {
    pub(in crate::screens::settings) fn account_keys_view(
        &self,
    ) -> Element<'_, crate::screens::settings::Message> {
        let keys = &self.account_keys;
        let mut column = widget::column::with_capacity(10)
            .spacing(theme::spacing().space_s)
            .push(widget::text::title3(t("accountPasskey.settingsTitle")))
            .push(widget::text::body(t("accountPasskey.settingsHint")));
        if self.busy {
            let element: Element<'_, Message> = column
                .push(widget::text::body(t("accountPasskey.browserPrompt")))
                .into();
            return element.map(crate::screens::settings::Message::AccountKeys);
        }
        column = column.push(
            widget::button::standard(t("accountPasskey.refreshKeys")).on_press(Message::Refresh),
        );
        if let Some(security) = &keys.security {
            column = column.push(widget::text::caption(format!(
                "{} · {}",
                security.user_id,
                if security.password_enabled {
                    t("accountPasskey.passwordEnabled")
                } else {
                    t("accountPasskey.passwordDisabled")
                }
            )));
            for key in &security.credentials {
                column = column.push(
                    widget::row::with_capacity(2)
                        .push(widget::text::body(format!(
                            "{} · {}",
                            key.name,
                            match key.mode {
                                PasskeyMode::AuthOnly => t("accountPasskey.authOnly"),
                                PasskeyMode::VaultUnlock => t("accountPasskey.full"),
                            }
                        )))
                        .push(
                            widget::button::destructive(t("common.delete"))
                                .on_press(Message::AskRevoke(key.credential_id.clone())),
                        ),
                );
            }
            if let Some(code) = &keys.code {
                column = column
                    .push(widget::text::body(t("accountPasskey.saveCode")))
                    .push(widget::text::monotext(code.code().to_owned()))
                    .push(
                        widget::text_input::secure_input(
                            t("accountPasskey.confirmCode"),
                            &keys.code_confirmation,
                            None,
                            true,
                        )
                        .on_input(Message::CodeConfirmation),
                    )
                    .push(
                        widget::toggler(keys.disable_password)
                            .label(t("accountPasskey.disablePassword"))
                            .on_toggle(Message::DisablePassword),
                    )
                    .push(
                        widget::button::suggested(t("accountPasskey.activateCode"))
                            .on_press(Message::ActivateCode),
                    );
            } else if !security.credentials.is_empty() {
                column = column.push(
                    widget::button::standard(t("accountPasskey.prepareCode"))
                        .on_press(Message::PrepareCode),
                );
            }
            let names: Vec<_> = keys.browsers.iter().map(|b| b.name.clone()).collect();
            column = column.push(widget::dropdown(names, keys.selected, Message::Browser));
            if keys.confirm_revoke.is_some() {
                column = column
                    .push(widget::text::body(t("accountPasskey.revokeConfirm")))
                    .push(
                        widget::button::destructive(t("accountPasskey.revoke"))
                            .on_press(Message::Revoke),
                    )
                    .push(widget::button::text(t("common.cancel")).on_press(Message::CancelRevoke));
            } else {
                column = column
                    .push(
                        widget::text_input::text_input(t("accountPasskey.keyName"), &keys.name)
                            .on_input(Message::Name),
                    )
                    .push(
                        widget::toggler(keys.auth_only)
                            .label(t("accountPasskey.authOnly"))
                            .on_toggle(Message::AuthOnly),
                    );
                if security.descriptor.is_none() && security.credentials.is_empty() {
                    column = column.push(
                        widget::text_input::secure_input(
                            t("accountPasskey.serverPassword"),
                            &keys.password,
                            None,
                            true,
                        )
                        .on_input(Message::Password),
                    );
                }
                column = column.push(
                    widget::button::suggested(t("accountPasskey.enroll")).on_press(Message::Enroll),
                );
            }
        }
        let element: Element<'_, Message> = column.into();
        element.map(crate::screens::settings::Message::AccountKeys)
    }
}
