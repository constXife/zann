//! Native sync detail content; the popover does not consume workspace geometry.
use super::*;

impl State {
    pub(super) fn sync_details_view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut content = widget::column::with_capacity(8).spacing(spacing.space_s);
        let close = widget::button::icon(widget::icon::from_name("window-close-symbolic"))
            .tooltip(t("common.close"))
            .on_press(Message::CloseSyncDetails);
        content = content.push(
            widget::row::with_capacity(2)
                .push(
                    widget::container(widget::text::title4(t("sync.details"))).width(Length::Fill),
                )
                .push(close)
                .spacing(spacing.space_s),
        );
        let indicator = self.sync_indicator_state();
        if let Some(state) = &indicator {
            let args = state.label_args();
            let args: Vec<_> = args
                .iter()
                .map(|(key, value)| (*key, value.as_str()))
                .collect();
            content = content.push(widget::text::body(t_args(state.label_key(), &args)));
        } else if self.sync_error().is_none() {
            content = content.push(widget::text::body(t("common.loading")));
        }
        let server = self
            .selected_storage_id()
            .and_then(|id| self.sync.servers.get(id));
        if let Some(state) = server.and_then(|s| s.state.as_ref()) {
            if let Some(url) = &state.server_url {
                content = content.push(widget::text::caption(url.clone()));
            }
            let last_synced = state.last_synced_at.as_deref().and_then(local_time_label);
            content = content.push(widget::text::caption(match last_synced {
                Some(time) => t_args("sync.lastSynced", &[("time", &time)]),
                None => t("sync.neverSynced"),
            }));
        }
        if let Some(error) = self.sync_error() {
            content = content
                .push(widget::text::caption(error))
                .push(widget::button::text(t("common.copy")).on_press(Message::CopySyncError));
        }
        if server.is_some_and(|s| s.read_error.is_some()) {
            content = content.push(
                widget::button::standard(t("common.retry")).on_press(Message::RefreshSyncDetails),
            );
        }
        if let Some(state) = indicator {
            let action = match state.action() {
                SyncAction::SyncNow => Some("settings.accounts.syncNow"),
                SyncAction::Reconnect => Some("settings.accounts.reconnect"),
                SyncAction::None => None,
            };
            if let Some(label) = action {
                content = content.push(
                    widget::button::standard(t(label)).on_press_maybe(
                        (!self.switching_context && self.sync.running_storage.is_none())
                            .then_some(Message::SyncNow),
                    ),
                );
            }
            if matches!(
                server.and_then(|s| s.failure.as_ref()),
                Some(local::SyncFailure::IdentityChanged)
            ) {
                content = content.push(
                    widget::button::standard(t("items.reviewStaleServer"))
                        .on_press(Message::ReviewStaleServer),
                );
            }
        }
        widget::container(widget::scrollable(content).height(Length::Shrink))
            .width(Length::Fixed(300.0))
            .max_height(440.0)
            .padding(spacing.space_m)
            .class(theme::Container::Dialog(true))
            .into()
    }
}
