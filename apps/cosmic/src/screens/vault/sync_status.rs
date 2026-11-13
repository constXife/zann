//! The sync indicator: what the open storage's sync looks like now, and the
//! one thing pressing it does. Which state shows comes from
//! `zann_ui_core::sync_status`; this screen supplies what it knows and draws it.
use chrono::{DateTime, Local};
use zann_client::app::local::StorageLink;
use zann_ui_core::{sync_indicator, SyncAction, SyncIndicator, SyncLink, SyncStatusInput};

use super::*;

impl State {
    pub(super) fn load_sync_state(session: &Session) -> Task<Message> {
        let facade = session.facade();
        cosmic::task::future(async move {
            Message::SyncStateLoaded(
                off_thread(move || {
                    let storage_id = local::current_storage_id(&facade)?;
                    local::sync_state(&facade, storage_id)
                })
                .await,
            )
        })
    }

    /// The indicator's state, once the open storage's sync state is known.
    pub fn sync_indicator_state(&self) -> Option<SyncIndicator> {
        let state = self.sync_state.as_ref()?;
        Some(sync_indicator(SyncStatusInput {
            link: match state.link {
                StorageLink::Connected => SyncLink::Connected,
                StorageLink::Disconnected => SyncLink::Disconnected,
            },
            server_url: state.server_url.as_deref(),
            pending_changes: state.pending_changes,
            syncing: self.syncing,
            failed: self.sync_error.is_some(),
        }))
    }

    pub(super) fn update_sync_status(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            // A failed read keeps the last known state rather than hiding it.
            Message::SyncStateLoaded(Ok(state)) => self.sync_state = Some(state),
            Message::SyncStateLoaded(Err(_)) => {}
            Message::SyncIndicatorPressed => {
                let Some(indicator) = self.sync_indicator_state() else {
                    return Outcome::None;
                };
                match indicator.action() {
                    SyncAction::SyncNow => {
                        if let Some(ticket) = session.auto_sync().take_now() {
                            return Outcome::Task(self.start_sync(ticket, session));
                        }
                    }
                    SyncAction::Reconnect => {
                        let Some(state) = self.sync_state.as_ref() else {
                            return Outcome::None;
                        };
                        let Ok(storage_id) = local::current_storage_id(&session.facade()) else {
                            return Outcome::None;
                        };
                        return Outcome::StaleServer(
                            storage_id,
                            local::SyncFailure::Disconnected {
                                server_url: state.server_url.clone(),
                                pending_changes: state.pending_changes,
                            },
                        );
                    }
                    SyncAction::None => {}
                }
            }
            _ => unreachable!("only sync status messages reach this handler"),
        }
        Outcome::None
    }

    /// The indicator beside the vault picker: an icon (with the count of
    /// unsent changes when there are any), its label and details in a tooltip.
    pub fn sync_indicator(&self) -> Option<Element<'_, Message>> {
        let indicator = self.sync_indicator_state()?;
        let args = indicator.label_args();
        let args = args
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect::<Vec<_>>();
        let label = t_args(indicator.label_key(), &args);
        let icon = match indicator {
            SyncIndicator::Disconnected { .. } => "network-offline-symbolic",
            SyncIndicator::Syncing { .. } => "emblem-synchronizing-symbolic",
            SyncIndicator::Failed { .. } => "dialog-warning-symbolic",
            SyncIndicator::Pending { .. } => "go-up-symbolic",
            SyncIndicator::Synced { .. } => "emblem-ok-symbolic",
        };
        let unsent = match &indicator {
            SyncIndicator::Pending {
                pending_changes, ..
            }
            | SyncIndicator::Failed {
                pending_changes, ..
            }
            | SyncIndicator::Disconnected {
                pending_changes, ..
            } if *pending_changes > 0 => Some(pending_changes.to_string()),
            _ => None,
        };
        let spacing = theme::spacing();
        let mut content = widget::row::with_capacity(2)
            .push(widget::icon::from_name(icon).size(16).icon())
            .spacing(spacing.space_xxxs)
            .align_y(Alignment::Center);
        if let Some(unsent) = unsent {
            content = content.push(widget::text::caption(unsent));
        }
        let mut button = widget::button::custom(content)
            .class(if indicator.needs_attention() {
                theme::Button::Destructive
            } else {
                theme::Button::Icon
            })
            .padding([4, 6]);
        if indicator.action() != SyncAction::None {
            button = button.on_press(Message::SyncIndicatorPressed);
        }
        let details = self.sync_details(&indicator);
        let tooltip = if details.is_empty() {
            label
        } else {
            format!("{label}\n{details}")
        };
        Some(
            widget::tooltip(
                button,
                widget::text::body(tooltip),
                widget::tooltip::Position::Bottom,
            )
            .into(),
        )
    }

    /// When the storage last synced, and what pressing the indicator does.
    fn sync_details(&self, indicator: &SyncIndicator) -> String {
        let mut lines = Vec::with_capacity(2);
        {
            let synced = self
                .sync_state
                .as_ref()
                .and_then(|state| state.last_synced_at.as_deref())
                .and_then(|at| DateTime::parse_from_rfc3339(at).ok());
            lines.push(match synced {
                Some(at) => t_args(
                    "sync.lastSynced",
                    &[("time", &local_time_label(&at.with_timezone(&Local)))],
                ),
                None => t("sync.neverSynced"),
            });
        }
        match indicator.action() {
            SyncAction::SyncNow => lines.push(t("sync.syncNowHint")),
            SyncAction::Reconnect => lines.push(t("sync.reconnectHint")),
            SyncAction::None => {}
        }
        lines.join("\n")
    }
}

/// Today's syncs show the time alone; older ones the date as well.
fn local_time_label(at: &DateTime<Local>) -> String {
    if at.date_naive() == Local::now().date_naive() {
        at.format("%H:%M").to_string()
    } else {
        at.format("%Y-%m-%d %H:%M").to_string()
    }
}
