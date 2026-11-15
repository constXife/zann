use super::*;
impl State {
    pub(in crate::screens::settings) fn view(&self) -> Element<'_, Message> {
        let mut column = widget::column::with_capacity(18)
            .spacing(theme::spacing().space_s)
            .push(widget::button::standard(t("backup.encryptedTitle")).on_press(Message::Export))
            .push(widget::button::standard(t("backup.restoreTitle")).on_press(Message::Restore));
        if !self.visible {
            return column.into();
        }
        if let Some(report) = &self.report {
            column = column.push(widget::text::caption(report));
        } else if let Some(inspection) = &self.inspection {
            column = column
                .push(widget::text::body(t_args(
                    "backup.verified",
                    &[("count", &inspection.items_count.to_string())],
                )))
                .push(widget::dropdown(
                    inspection
                        .storages
                        .iter()
                        .map(|s| s.name.clone())
                        .collect::<Vec<_>>(),
                    self.source,
                    Message::Source,
                ))
                .push(widget::text::caption(t("backup.target")))
                .push(widget::dropdown(
                    self.targets
                        .iter()
                        .map(|s| {
                            zann_ui_core::sync_status::storage_context_label(
                                &s.name,
                                s.server_url.as_deref(),
                                s.account_name.as_deref(),
                            )
                        })
                        .collect::<Vec<_>>(),
                    self.target,
                    Message::Target,
                ));
            let mut restore = widget::button::suggested(t("backup.restore"));
            if !self.busy && self.handle.is_some() && self.source.is_some() && self.target.is_some()
            {
                restore = restore.on_press(Message::Import);
            }
            column = column.push(restore);
        } else if self.restoring {
            let mut choose = widget::button::standard(t("backup.choose"));
            if !self.busy {
                choose = choose.on_press(Message::Choose);
            }
            column = column.push(choose);
            if !self.recipients.is_empty() {
                column = column.push(widget::dropdown(
                    self.recipients
                        .iter()
                        .map(|r| format!("{} {}", label(r.kind), r.index + 1))
                        .collect::<Vec<_>>(),
                    self.slot,
                    Message::Slot,
                ));
                if let Some(slot) = self.slot.and_then(|i| self.recipients.get(i)) {
                    column = column.push(self.credentials(slot.kind));
                    let mut open = widget::button::suggested(t("backup.open"));
                    if !self.busy {
                        open = open.on_press(Message::Unlock);
                    }
                    column = column.push(open);
                }
            }
        } else if let Some(caps) = &self.capabilities {
            column = column
                .push(widget::text::caption(t("backup.portableHelp")))
                .push(widget::dropdown(
                    caps.recipients
                        .iter()
                        .map(|kind| label(*kind))
                        .collect::<Vec<_>>(),
                    Some(self.kind),
                    Message::Kind,
                ));
            if let Some(kind) = caps.recipients.get(self.kind) {
                column = column.push(self.credentials(*kind));
            }
            let mut add = widget::button::standard(t("backup.addRecipient"));
            if !self.busy
                && self.handle.is_some()
                && self.recipients.len() < caps.max_recipients as usize
            {
                add = add.on_press(Message::Add);
            }
            column = column.push(add);
            for recipient in &self.recipients {
                column = column.push(widget::text::caption(format!(
                    "{}. {}",
                    recipient.index + 1,
                    label(recipient.kind)
                )));
            }
            let mut save = widget::button::suggested(t("backup.save"));
            if !self.busy && self.handle.is_some() {
                save = save.on_press(Message::Save);
            }
            column = column.push(save);
        }
        if let Some(error) = &self.error {
            column = column.push(widget::text::caption(error));
        }
        if self.busy {
            column = column.push(widget::text::caption(t("common.loading")));
        }
        column
            .push(widget::button::standard(t("common.cancel")).on_press(Message::Cancel))
            .into()
    }
    fn credentials(&self, kind: BackupRecipientKind) -> Element<'_, Message> {
        match kind {
            BackupRecipientKind::Passphrase => widget::text_input::secure_input(
                t("backup.passphrase"),
                &self.phrase,
                None::<Message>,
                true,
            )
            .on_input(Message::Phrase)
            .into(),
            BackupRecipientKind::Hardware => widget::column::with_capacity(3)
                .push(widget::text::caption(t("backup.hardwareHelp")))
                .push(
                    widget::text_input::secure_input(
                        t("export.pin"),
                        &self.pin,
                        None::<Message>,
                        true,
                    )
                    .on_input(Message::Pin),
                )
                .push(
                    widget::toggler(self.built_in_uv)
                        .label(t("backup.builtInUV"))
                        .on_toggle(Message::BuiltInUV),
                )
                .into(),
            BackupRecipientKind::Biometric => {
                widget::text::caption(t("backup.biometricHelp")).into()
            }
        }
    }
}
fn label(kind: BackupRecipientKind) -> String {
    t(match kind {
        BackupRecipientKind::Passphrase => "backup.passphrase",
        BackupRecipientKind::Hardware => "export.hardware",
        BackupRecipientKind::Biometric => "export.biometric",
    })
}
