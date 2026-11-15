//! Connected servers and explicit reconnection controls.
use super::*;

fn storage_label(storage: &StorageSummary) -> String {
    zann_ui_core::sync_status::storage_context_label(
        &storage.name,
        storage.server_url.as_deref(),
        storage.account_name.as_deref(),
    )
}

impl State {
    pub(super) fn accounts(&self) -> Element<'_, Message> {
        let mut section =
            widget::settings::section().title(t("settings.accounts.connectedServers"));
        let remotes: Vec<&StorageSummary> = self
            .storages
            .iter()
            .filter(|storage| storage.kind == "remote")
            .collect();
        if remotes.is_empty() {
            section = section.add(widget::text::body(t("settings.accounts.noServers")));
        }
        for storage in remotes {
            if let Some(stale) = self
                .stale_server
                .as_ref()
                .filter(|stale| stale.storage_id == storage.id)
            {
                section = section.add(self.stale_server_row(storage, stale));
                continue;
            }
            if let Some(gone) = self
                .disconnected
                .as_ref()
                .filter(|gone| gone.storage_id == storage.id)
            {
                section = section.add(self.disconnected_row(storage, gone));
                continue;
            }
            let mut sync = widget::button::standard(t("settings.accounts.syncNow"));
            if !self.syncing {
                sync = sync.on_press(Message::SyncNow(storage.id.clone()));
            }
            section =
                section.add(widget::settings::item::builder(storage_label(storage)).control(sync));
        }
        section = section.add(
            widget::settings::item::builder(t("settings.accounts.addServer")).control(
                widget::button::standard(t("wizard.connect")).on_press(Message::AddServer),
            ),
        );
        widget::settings::view_column(vec![section.into()]).into()
    }

    /// The server storage no connection syncs: why, with its unsent changes,
    /// in place of its sync control, and the way back to its server.
    fn disconnected_row<'a>(
        &self,
        storage: &'a StorageSummary,
        gone: &Disconnected,
    ) -> Element<'a, Message> {
        let mut reconnect = widget::button::suggested(t("settings.accounts.reconnect"));
        if !self.busy && !self.syncing {
            reconnect = reconnect.on_press(Message::Reconnect);
        }
        let reason = local::SyncFailure::Disconnected {
            server_url: gone.server_url.clone(),
            pending_changes: gone.pending_changes,
        };
        widget::column::with_capacity(3)
            .push(widget::text::body(storage_label(storage)))
            .push(widget::text::caption(reason.to_string()))
            .push(reconnect)
            .spacing(theme::spacing().space_xxs)
            .width(Length::Fill)
            .into()
    }

    /// The account whose server changed its identity: the error in place of
    /// its sync control, and the way out, behind a confirmation that says
    /// what stays on this device.
    fn stale_server_row<'a>(
        &self,
        storage: &'a StorageSummary,
        stale: &StaleServer,
    ) -> Element<'a, Message> {
        let spacing = theme::spacing();
        let idle = !self.busy && !self.syncing;
        let mut column = widget::column::with_capacity(4)
            .push(widget::text::body(storage_label(storage)))
            .push(widget::text::caption(t("errors.server_identity_changed")))
            .spacing(spacing.space_xxs)
            .width(Length::Fill);

        if !stale.confirming {
            let mut forget = widget::button::standard(match stale.pending_changes {
                Some(_) => t("settings.accounts.forgetServer"),
                None => t("common.loading"),
            });
            if idle && stale.pending_changes.is_some() {
                forget = forget.on_press(Message::AskForget);
            }
            return column.push(forget).into();
        }

        column = column.push(widget::text::body(t_args(
            "settings.accounts.forgetServerConfirm",
            &[("server", &storage_label(storage))],
        )));
        if let Some(count) = stale.pending_changes.filter(|count| *count > 0) {
            column = column.push(widget::text::caption(t_args(
                "settings.accounts.forgetServerPending",
                &[("count", &count.to_string())],
            )));
        }
        let mut confirm = widget::button::destructive(t("settings.accounts.forgetServer"));
        let mut cancel = widget::button::standard(t("common.cancel"));
        if idle {
            confirm = confirm.on_press(Message::ConfirmForget);
            cancel = cancel.on_press(Message::CancelForget);
        }
        column
            .push(
                widget::row::with_capacity(2)
                    .push(confirm)
                    .push(cancel)
                    .spacing(spacing.space_xs),
            )
            .into()
    }
}
