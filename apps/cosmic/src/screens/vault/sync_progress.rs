//! Bounded metadata relay and correlated cache refreshes during a network pull.
use super::*;
mod relay;
pub(super) use relay::sync_task;

pub(super) struct ProgressView {
    pub initial_target: Option<String>,
    pub awaiting_first: bool,
    pub failure: Option<String>,
    pub run: u64,
    pub running: bool,
    pub refreshing: bool,
    pub pending: bool,
}

impl Default for ProgressView {
    fn default() -> Self {
        Self {
            initial_target: None,
            awaiting_first: false,
            failure: None,
            run: crate::backend::next_view_request(),
            running: false,
            refreshing: false,
            pending: false,
        }
    }
}

impl State {
    pub fn set_initial_sync_target(&mut self, target: Option<String>, awaiting_first: bool) {
        self.progress.initial_target = target;
        self.progress.awaiting_first = awaiting_first;
    }

    pub fn awaiting_first_sync(&self) -> bool {
        self.progress.awaiting_first
            && self.selected_storage_id().is_none_or(|id| {
                self.progress
                    .initial_target
                    .as_deref()
                    .is_none_or(|target| id == target)
            })
    }

    pub fn sync_run_id(&self) -> u64 {
        self.progress.run
    }

    pub(super) fn queue_committed_refresh(&mut self, session: &Session) -> Task<Message> {
        if self.progress.refreshing {
            self.progress.pending = true;
            Task::none()
        } else {
            self.refresh_committed(session)
        }
    }

    fn refresh_committed(&mut self, session: &Session) -> Task<Message> {
        self.progress.refreshing = true;
        self.progress.pending = false;
        let (run, list_generation, context_request) = (
            self.progress.run,
            self.list_generation,
            self.workspace.request,
        );
        let facade = session.facade();
        let query = (!self.applied_query.is_empty()).then(|| self.applied_query.clone());
        let dates = self.applied_dates;
        let keeping = (self.items.len() as u32).max(local::PAGE_LIMIT);
        cosmic::task::future(async move {
            Message::ProgressWorkspaceLoaded {
                run,
                list_generation,
                context_request,
                result: off_thread(move || {
                    Ok((
                        local::vault_context(&facade)?,
                        local::items_page(&facade, None, query, dates, keeping)?,
                    ))
                })
                .await,
            }
        })
    }

    pub(super) fn update_sync_progress(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::SyncCommitted { run, storage_id } => {
                if run != self.progress.run {
                    return Outcome::None;
                }
                if self.progress.awaiting_first && self.progress.initial_target.is_none() {
                    self.progress.initial_target = Some(storage_id.clone());
                }
                if self.progress.running {
                    self.sync.running_storage = Some(storage_id.clone());
                }
                if self
                    .selected_storage_id()
                    .is_some_and(|id| id != storage_id)
                    || self.switching_context
                    || self.editor.is_some()
                    || self.history.is_some()
                {
                    return Outcome::None;
                }
                return Outcome::Task(self.queue_committed_refresh(session));
            }
            Message::ProgressWorkspaceLoaded {
                run,
                list_generation,
                context_request,
                result,
            } => {
                if run != self.progress.run || !self.progress.refreshing {
                    return Outcome::None;
                }
                self.progress.refreshing = false;
                if list_generation == self.list_generation
                    && context_request == self.workspace.request
                    && !self.switching_context
                    && !self.searching
                    && !self.busy
                    && self.editor.is_none()
                    && self.history.is_none()
                {
                    match result {
                        Ok((context, page))
                            if self.selected_storage_id().is_none()
                                || (context.current_storage_id.as_deref()
                                    == self.selected_storage_id()
                                    && (context.current_vault_id == self.selected_vault_id
                                        // The first committed catalog gives a server
                                        // its first vault; no user selection exists yet.
                                        || (self.awaiting_first_sync()
                                            && self.selected_vault_id.is_none()
                                            && self.vaults.is_empty()))) =>
                        {
                            if !self.progress.running && self.progress.failure.is_none() {
                                self.progress.awaiting_first = false;
                            }
                            self.apply_context(context);
                            // Supersede any metadata read started before this committed snapshot.
                            self.workspace.request = crate::backend::next_view_request();
                            self.apply_page(page, true);
                            self.reconcile_selection();
                            self.rebuild_nav();
                            if self.progress.pending {
                                return Outcome::Task(self.refresh_committed(session));
                            }
                            let metadata = self.load_selected_sync_state(session);
                            let detail = if !self.progress.running {
                                self.selected_item_id()
                                    .map(str::to_owned)
                                    .map(|id| self.load_detail(id, session))
                                    .unwrap_or_else(Task::none)
                            } else {
                                Task::none()
                            };
                            return Outcome::Task(Task::batch([metadata, detail]));
                        }
                        Ok(_) => {}
                        Err(error) => self.list_error = Some(error),
                    }
                }
                if self.progress.pending {
                    return Outcome::Task(self.refresh_committed(session));
                }
            }
            _ => unreachable!("only committed cache messages reach this handler"),
        }
        Outcome::None
    }
}
