//! Restricted recovery widgets; authority and code custody stay in the client.
use super::*;
use cosmic::{theme, widget, Element};
use zann_core::api::account_access::PasskeyMode;
use zann_flows::recovery::Phase;
impl State {
    pub(in crate::screens::connect) fn recovery_view(&self) -> Option<Element<'_, Event>> {
        let recovery = self.recovery.as_ref()?;
        let snapshot = recovery.flow.snapshot();
        let mut column = widget::column::with_capacity(12)
            .spacing(theme::spacing().space_s)
            .push(widget::text::title3(crate::i18n::t(
                "accountRecovery.title",
            )));
        let mut completed = false;
        if snapshot.busy {
            column = column.push(widget::text::body(crate::i18n::t(
                "accountPasskey.browserPrompt",
            )));
        } else {
            match snapshot.phase {
                Phase::Completed => {
                    completed = true;
                    column = column.push(widget::text::body(crate::i18n::t(
                        "accountRecovery.completed",
                    )));
                }
                Phase::Stopped => {
                    column = column.push(widget::text::body(crate::i18n::t(
                        "accountRecovery.stopped",
                    )));
                }
                Phase::Recover {
                    consumed,
                    candidate,
                    restart,
                    editable,
                    name,
                    mode,
                    password_required,
                } => {
                    if !consumed {
                        column = column
                            .push(
                                widget::text_input::secure_input(
                                    crate::i18n::t("accountRecovery.oldCode"),
                                    &recovery.old_code,
                                    None,
                                    true,
                                )
                                .on_input(Message::OldCode),
                            )
                            .push(
                                widget::button::text(crate::i18n::t(
                                    "accountRecovery.retryConsume",
                                ))
                                .on_press(Message::RetryConsume),
                            );
                    }
                    column = column.push(
                        widget::button::text(crate::i18n::t("accountRecovery.resume"))
                            .on_press(Message::ResumeCurrent),
                    );
                    if consumed {
                        if candidate {
                            column = column.push(
                                widget::toggler(restart)
                                    .label(crate::i18n::t("accountRecovery.restartEnrollment"))
                                    .on_toggle(Message::Restart),
                            );
                        }
                        if editable {
                            column = column
                                .push(
                                    widget::text_input::text_input(
                                        crate::i18n::t("accountPasskey.keyName"),
                                        name,
                                    )
                                    .on_input(Message::Name),
                                )
                                .push(
                                    widget::toggler(mode == PasskeyMode::AuthOnly)
                                        .label(crate::i18n::t("accountPasskey.authOnly"))
                                        .on_toggle(Message::AuthOnly),
                                );
                        } else {
                            column = column.push(widget::text::body(name.to_owned()));
                        }
                        if password_required {
                            column = column.push(
                                widget::text_input::secure_input(
                                    crate::i18n::t("accountRecovery.encryptionPassword"),
                                    &recovery.password,
                                    None,
                                    true,
                                )
                                .on_input(Message::Password),
                            );
                        }
                        for browser in &self.pairings {
                            column = column.push(
                                widget::button::suggested(browser.name.clone())
                                    .on_press(Message::Continue(browser.public_key.clone())),
                            );
                        }
                    }
                }
                Phase::Confirm {
                    successor_code,
                    pending,
                } => {
                    column = column
                        .push(widget::text::body(crate::i18n::t(
                            "accountPasskey.saveCode",
                        )))
                        .push(widget::text::monotext(successor_code.to_owned()))
                        .push(
                            widget::text_input::secure_input(
                                crate::i18n::t("accountPasskey.confirmCode"),
                                &recovery.confirmation,
                                None,
                                true,
                            )
                            .on_input(Message::Confirmation),
                        )
                        .push(
                            widget::text_input::secure_input(
                                crate::i18n::t("accountRecovery.oldCode"),
                                &recovery.old_code,
                                None,
                                true,
                            )
                            .on_input(Message::OldCode),
                        )
                        .push(
                            widget::button::destructive(crate::i18n::t("accountRecovery.consume"))
                                .on_press_maybe(
                                    recovery
                                        .flow
                                        .can_consume(&recovery.confirmation)
                                        .then_some(Message::Consume),
                                ),
                        );
                    for (index, handle) in pending.iter().enumerate() {
                        column = column.push(
                            widget::button::standard(format!(
                                "{} · {}",
                                crate::i18n::t("accountRecovery.resume"),
                                handle.operation_id
                            ))
                            .on_press(Message::ResumePending(index)),
                        );
                    }
                }
                Phase::Locate { locator } => {
                    column = column
                        .push(
                            widget::text_input::text_input("you@example.com", locator)
                                .on_input(Message::Locator),
                        )
                        .push(
                            widget::button::standard(crate::i18n::t("accountRecovery.prepare"))
                                .on_press(Message::Prepare),
                        );
                }
            }
        }
        if let Some(error) = snapshot.error {
            column = column.push(widget::text::caption(error.to_owned()));
        }
        let body: Element<'_, Message> = column
            .push(widget::button::text(crate::i18n::t("wizard.back")).on_press(Message::Back))
            .into();
        let body = body.map(crate::screens::connect::Message::Recovery);
        let mut content = widget::column::with_capacity(2)
            .push(body)
            .spacing(theme::spacing().space_s);
        if !snapshot.busy && !completed {
            content = content.push(self.browser_controls(false));
        }
        let generation = self.generation;
        Some(crate::screens::centered(content).map(move |message| Event {
            generation,
            message,
        }))
    }
}
