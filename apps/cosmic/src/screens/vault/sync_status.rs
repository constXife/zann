//! Storage-scoped sync feedback. State/action policy stays in zann-ui-core;
//! this adapter owns the native nonmodal popover and metadata read requests.
use super::*;
use chrono::{DateTime, Local};
use std::collections::HashMap;
use zann_client::app::local::StorageLink;
use zann_ui_core::{sync_indicator, SyncAction, SyncIndicator, SyncLink, SyncStatusInput};

#[derive(Default)]
pub(super) struct ServerSync {
    pub state: Option<local::StorageSyncState>,
    pub failure: Option<local::SyncFailure>,
    pub read_error: Option<String>,
    pub request: u64,
}
pub(super) struct SyncView {
    pub servers: HashMap<String, ServerSync>,
    pub running_storage: Option<String>,
    pub showing_details: bool,
    initial_error: Option<String>,
}
impl SyncView {
    pub fn new(initial_error: Option<String>) -> Self {
        Self {
            servers: HashMap::new(),
            running_storage: None,
            showing_details: false,
            initial_error,
        }
    }
}

impl State {
    pub(super) fn bind_sync_context(&mut self) {
        self.sync.servers.retain(|id, _| {
            self.workspace.storages.iter().any(|s| &s.id == id)
                || self.sync.running_storage.as_ref() == Some(id)
        });
        if let Some(id) = &self.workspace.storage_id {
            let server = self.sync.servers.entry(id.clone()).or_default();
            if let Some(error) = self.sync.initial_error.take() {
                server.failure = Some(local::SyncFailure::Other(error));
            }
        }
    }
    pub fn sync_details_open(&self) -> bool {
        self.sync.showing_details
    }
    pub fn syncing(&self) -> bool {
        self.selected_storage_id().is_some()
            && self.sync.running_storage.as_deref() == self.selected_storage_id()
    }
    pub fn sync_error(&self) -> Option<String> {
        let server = self.sync.servers.get(self.selected_storage_id()?)?;
        server
            .failure
            .as_ref()
            .map(|failure| t_args("items.syncFailed", &[("error", &failure.to_string())]))
            .or_else(|| server.read_error.clone())
    }
    pub(super) fn load_selected_sync_state(&mut self, session: &Session) -> Task<Message> {
        match self.workspace.storage_id.clone() {
            Some(id) => self.load_sync_state(session, id),
            None => Task::none(),
        }
    }
    pub(super) fn load_sync_state(
        &mut self,
        session: &Session,
        storage_id: String,
    ) -> Task<Message> {
        let request = crate::backend::next_view_request();
        self.sync
            .servers
            .entry(storage_id.clone())
            .or_default()
            .request = request;
        let facade = session.facade();
        cosmic::task::future(async move {
            let target = storage_id.clone();
            Message::SyncStateLoaded {
                storage_id,
                request,
                result: off_thread(move || local::sync_state(&facade, target)).await,
            }
        })
    }
    pub fn sync_state_request_id(&self, storage_id: &str) -> Option<u64> {
        self.sync.servers.get(storage_id).map(|s| s.request)
    }
    pub fn sync_indicator_state(&self) -> Option<SyncIndicator> {
        let server = self.sync.servers.get(self.selected_storage_id()?)?;
        let state = server.state.as_ref()?;
        Some(sync_indicator(SyncStatusInput {
            link: match state.link {
                StorageLink::Connected => SyncLink::Connected,
                StorageLink::Disconnected => SyncLink::Disconnected,
            },
            server_url: state.server_url.as_deref(),
            pending_changes: state.pending_changes,
            syncing: self.syncing(),
            failed: server.failure.is_some() || server.read_error.is_some(),
        }))
    }
    pub(super) fn update_sync_status(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::SyncStateLoaded {
                storage_id,
                request,
                result,
            } => {
                let Some(server) = self.sync.servers.get_mut(&storage_id) else {
                    return Outcome::None;
                };
                if server.request != request {
                    return Outcome::None;
                }
                match result {
                    Ok(state) => {
                        server.state = Some(state);
                        server.read_error = None;
                    }
                    Err(error) => server.read_error = Some(error),
                }
            }
            Message::SyncIndicatorPressed => {
                if self.selected_storage_id().is_none() {
                    return Outcome::None;
                }
                self.sync.showing_details = !self.sync.showing_details;
                if self.sync.showing_details {
                    return Outcome::Task(self.load_selected_sync_state(session));
                }
            }
            Message::RefreshSyncDetails => {
                return Outcome::Task(self.load_selected_sync_state(session))
            }
            Message::CloseSyncDetails => self.sync.showing_details = false,
            Message::CopySyncError => {
                if let Some(value) = self.sync_error() {
                    return Outcome::Copy {
                        value,
                        feedback: Task::none(),
                    };
                }
            }
            Message::SyncNow => {
                if self.switching_context || self.sync.running_storage.is_some() {
                    return Outcome::None;
                }
                match self.sync_indicator_state().map(|s| s.action()) {
                    Some(SyncAction::SyncNow) => {
                        if let Some(ticket) = session.auto_sync().take_now() {
                            return Outcome::Task(self.start_sync(ticket, session));
                        }
                    }
                    Some(SyncAction::Reconnect) => {
                        let Some(id) = self.workspace.storage_id.clone() else {
                            return Outcome::None;
                        };
                        let Some(state) = self.sync.servers.get(&id).and_then(|s| s.state.as_ref())
                        else {
                            return Outcome::None;
                        };
                        self.sync.showing_details = false;
                        return Outcome::StaleServer(
                            id,
                            local::SyncFailure::Disconnected {
                                server_url: state.server_url.clone(),
                                pending_changes: state.pending_changes,
                            },
                        );
                    }
                    _ => {}
                }
            }
            Message::ReviewStaleServer => {
                let Some(id) = self.workspace.storage_id.clone() else {
                    return Outcome::None;
                };
                if let Some(
                    failure @ (local::SyncFailure::IdentityChanged
                    | local::SyncFailure::Disconnected { .. }),
                ) = self.sync.servers.get(&id).and_then(|s| s.failure.as_ref())
                {
                    self.sync.showing_details = false;
                    return Outcome::StaleServer(id, failure.clone());
                }
            }
            _ => unreachable!("only sync status messages reach this handler"),
        }
        Outcome::None
    }
    pub fn sync_indicator(&self) -> Option<Element<'_, Message>> {
        self.selected_storage_id()?;
        let state = self.sync_indicator_state();
        let attention = state.as_ref().is_some_and(SyncIndicator::needs_attention)
            || self.sync_error().is_some();
        let icon = state.as_ref().map(sync_icon).unwrap_or(if attention {
            "dialog-warning-symbolic"
        } else {
            "emblem-synchronizing-symbolic"
        });
        let content: Element<'_, Message> = if self.syncing() {
            widget::progress_bar::indeterminate_circular()
                .size(16.0)
                .into()
        } else {
            widget::icon::from_name(icon).size(16).icon().into()
        };
        let button = widget::button::custom(
            widget::container(content)
                .width(Length::Fixed(16.0))
                .height(Length::Fixed(16.0)),
        )
        .class(if attention {
            theme::Button::Destructive
        } else {
            theme::Button::Icon
        })
        .padding(4)
        .on_press(Message::SyncIndicatorPressed);
        let mut popup = widget::popover(button)
            .position(widget::popover::Position::Bottom)
            .on_close(Message::CloseSyncDetails);
        if self.sync.showing_details {
            popup = popup.popup(self.sync_details_view());
        }
        Some(if self.sync.showing_details {
            popup.into()
        } else {
            widget::tooltip(
                popup,
                widget::text::body(t("sync.details")),
                widget::tooltip::Position::Bottom,
            )
            .into()
        })
    }
}

pub(super) fn sync_icon(indicator: &SyncIndicator) -> &'static str {
    match indicator {
        SyncIndicator::Disconnected { .. } => "network-wired-disconnected-symbolic",
        SyncIndicator::Syncing { .. } => "emblem-synchronizing-symbolic",
        SyncIndicator::Failed { .. } => "dialog-warning-symbolic",
        SyncIndicator::Pending { .. } => "go-up-symbolic",
        SyncIndicator::Synced { .. } => "emblem-ok-symbolic",
    }
}
pub(super) fn local_time_label(at: &str) -> Option<String> {
    let at = DateTime::parse_from_rfc3339(at).ok()?.with_timezone(&Local);
    Some(if at.date_naive() == Local::now().date_naive() {
        at.format("%H:%M").to_string()
    } else {
        at.format("%Y-%m-%d %H:%M").to_string()
    })
}

mod details;
