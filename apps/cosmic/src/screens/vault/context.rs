//! Native server/vault navigation, independent of network synchronization.
use zann_client::app::local::StorageSummary;
use zann_ui_core::sync_status::storage_context_label;

use super::*;

pub(super) struct Workspace {
    pub storages: Vec<StorageSummary>,
    pub storage_id: Option<String>,
    pub request: u64,
}

impl Workspace {
    pub fn new() -> Self {
        Self {
            storages: Vec::new(),
            storage_id: None,
            request: crate::backend::next_view_request(),
        }
    }
}

impl State {
    pub fn context_request_id(&self) -> u64 {
        self.workspace.request
    }
    pub fn selected_storage_id(&self) -> Option<&str> {
        self.workspace.storage_id.as_deref()
    }
    pub fn offers_vault_picker(&self) -> bool {
        self.vaults.len() > 1
    }

    pub fn load_vaults(&mut self, session: &Session) -> Task<Message> {
        // A read must not supersede the completion of an admitted core write.
        // That completion already includes the fresh context projection.
        if self.switching_context {
            return Task::none();
        }
        self.workspace.request = crate::backend::next_view_request();
        let request = self.workspace.request;
        let facade = session.facade();
        cosmic::task::future(async move {
            Message::VaultsLoaded {
                request,
                result: off_thread(move || local::vault_context(&facade)).await,
            }
        })
    }

    pub(super) fn apply_context(&mut self, context: local::VaultContext) {
        self.workspace.storages = context.storages;
        self.workspace.storage_id = context.current_storage_id;
        self.vaults = context.vaults;
        self.selected_vault_id = context.current_vault_id;
        self.bind_sync_context();
        self.rebuild_nav();
    }

    pub(super) fn update_context(&mut self, message: Message, session: &Session) -> Outcome {
        let target = match message {
            Message::VaultsLoaded { request, result } => {
                if request != self.workspace.request || self.switching_context {
                    return Outcome::None;
                }
                match result {
                    Ok(context) => {
                        self.apply_context(context);
                        return Outcome::Task(Task::batch([
                            self.load_selected_sync_state(session),
                            self.arm_auto_sync(session),
                        ]));
                    }
                    Err(error) => self.error = Some(error),
                }
                return Outcome::None;
            }
            Message::ContextSwitched { request, change } => {
                if request != self.workspace.request || !self.switching_context {
                    return Outcome::None;
                }
                self.switching_context = false;
                self.busy = false;
                let changed = self.workspace.storage_id != change.storage_id
                    || self.selected_vault_id != change.vault_id;
                self.workspace.storage_id = change.storage_id;
                self.selected_vault_id = change.vault_id;
                match change.result {
                    Ok((context, page)) => {
                        self.apply_context(context);
                        match page {
                            Ok(page) => self.replace_page(page),
                            Err(error) => {
                                self.clear_context_items();
                                self.list_error = Some(error);
                            }
                        }
                    }
                    Err(error) => {
                        if changed {
                            self.clear_context_items();
                            self.vaults.clear();
                            self.nav.clear();
                        }
                        self.error = Some(error);
                    }
                }
                return Outcome::Task(Task::batch([
                    self.load_selected_sync_state(session),
                    self.arm_auto_sync(session),
                ]));
            }
            Message::SelectStorage(index) => {
                let Some(storage) = self.workspace.storages.get(index) else {
                    return Outcome::None;
                };
                if self.selected_storage_id() == Some(storage.id.as_str()) && self.error.is_none() {
                    return Outcome::None;
                }
                local::ContextTarget::Storage(storage.id.clone())
            }
            Message::SelectVault(index) => {
                let Some(vault) = self.vaults.get(index) else {
                    return Outcome::None;
                };
                if self.selected_vault_id.as_deref() == Some(vault.id.as_str())
                    && self.error.is_none()
                {
                    return Outcome::None;
                }
                local::ContextTarget::Vault(vault.id.clone())
            }
            _ => unreachable!("only navigation messages reach this handler"),
        };
        // Network sync never enters this admission condition. Only another
        // local context change or an open draft/history owns navigation.
        if self.switching_context || self.editor.is_some() || self.history.is_some() {
            return Outcome::None;
        }
        self.workspace.request = crate::backend::next_view_request();
        let request = self.workspace.request;
        self.list_generation = self.list_generation.wrapping_add(1);
        self.searching = false;
        self.clear_selection();
        self.sync.showing_details = false;
        self.switching_context = true;
        self.busy = true;
        self.error = None;
        let facade = session.facade();
        let selection = facade.clone();
        Outcome::Task(cosmic::task::future(async move {
            let change = off_thread(move || Ok(local::switch_context(&facade, target))).await;
            match change {
                Ok(change) => Message::ContextSwitched { request, change },
                Err(error) => Message::ContextSwitched {
                    request,
                    change: local::ContextChange {
                        storage_id: selection.current_storage_id(),
                        vault_id: selection.current_vault_id(),
                        result: Err(error),
                    },
                },
            }
        }))
    }

    fn clear_context_items(&mut self) {
        self.items.clear();
        self.next_cursor = None;
        self.total = 0;
        self.counts = ItemCounts::default();
        self.query.clear();
        self.applied_query.clear();
        self.clear_selection();
    }

    pub fn nav_header(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let selected = self
            .workspace
            .storages
            .iter()
            .position(|s| Some(s.id.as_str()) == self.selected_storage_id());
        let server: Element<'_, Message> = if self.workspace.storages.len() > 1 {
            let labels: Vec<_> = self
                .workspace
                .storages
                .iter()
                .map(|s| storage_context_label(&s.name, s.server_url.as_deref()))
                .collect();
            let dropdown =
                widget::dropdown(labels, selected, Message::SelectStorage).width(Length::Fill);
            dropdown.into()
        } else if let Some(storage) = selected.and_then(|i| self.workspace.storages.get(i)) {
            widget::text::body(storage_context_label(
                &storage.name,
                storage.server_url.as_deref(),
            ))
            .into()
        } else {
            widget::text::body(t("nav.serverAccount")).into()
        };
        let mut row = widget::row::with_capacity(2)
            .push(widget::container(server).width(Length::Fill))
            .align_y(Alignment::Center);
        if let Some(indicator) = self.sync_indicator() {
            row = row.push(indicator);
        }
        let selected = self
            .selected_vault_id
            .as_deref()
            .and_then(|id| self.vaults.iter().position(|v| v.id == id));
        let vault: Element<'_, Message> = if self.offers_vault_picker() {
            let labels: Vec<_> = self.vaults.iter().map(vault_label).collect();
            widget::dropdown(labels, selected, Message::SelectVault).into()
        } else {
            widget::text::caption(
                selected
                    .and_then(|i| self.vaults.get(i))
                    .map(vault_label)
                    .unwrap_or_default(),
            )
            .into()
        };
        widget::column::with_capacity(2)
            .push(row)
            .push(vault)
            .spacing(spacing.space_xxs)
            .padding(spacing.space_s)
            .width(Length::Fill)
            .into()
    }
}
