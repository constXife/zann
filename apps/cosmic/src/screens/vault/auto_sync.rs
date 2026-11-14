//! Automatic sync admission stays in the core schedule. A network completion
//! updates only its source server; list reads are separate correlated effects.
use super::*;
use zann_client::app::local::AUTO_SYNC_DEBOUNCE;

impl State {
    pub fn arm_auto_sync(&mut self, session: &Session) -> Task<Message> {
        let now = Instant::now();
        let due = session
            .auto_sync()
            .next_due()
            .unwrap_or(now + AUTO_SYNC_DEBOUNCE);
        self.sync_timer = crate::backend::next_view_request();
        let timer = self.sync_timer;
        cosmic::task::future(async move {
            tokio::time::sleep_until(due.into()).await;
            Message::SyncDue(timer)
        })
    }
    pub(super) fn local_change(&mut self, session: &Session) -> Task<Message> {
        session.auto_sync().local_change(Instant::now());
        Task::batch([
            self.arm_auto_sync(session),
            self.load_selected_sync_state(session),
        ])
    }
    pub(super) fn start_sync(
        &mut self,
        ticket: AutoSyncTicket,
        session: &Session,
    ) -> Task<Message> {
        let Some(storage_id) = self.workspace.storage_id.clone() else {
            session.auto_sync().finished(ticket, Instant::now());
            return self.arm_auto_sync(session);
        };
        self.sync.running_storage = Some(storage_id.clone());
        let list_generation = self.list_generation;
        let facade = session.facade();
        cosmic::task::future(async move {
            let target = storage_id.clone();
            let result = off_thread(move || Ok(local::sync(&facade, Some(target))))
                .await
                .unwrap_or_else(|error| Err(local::SyncFailure::Other(error)));
            Message::AutoSynced {
                ticket,
                storage_id,
                list_generation,
                result,
            }
        })
    }
    pub(super) fn update_auto_sync(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::SyncDue(timer) => {
                if timer != self.sync_timer {
                    return Outcome::None;
                }
                // Context completion rearms the schedule; do not spin on an overdue timer.
                if self.switching_context || self.selected_storage_id().is_none() {
                    return Outcome::None;
                }
                let Some(ticket) = session.auto_sync().take_due(Instant::now()) else {
                    return Outcome::Task(self.arm_auto_sync(session));
                };
                Outcome::Task(self.start_sync(ticket, session))
            }
            Message::AutoSynced {
                ticket,
                storage_id,
                list_generation,
                result,
            } => {
                if !session.auto_sync().finished(ticket, Instant::now()) {
                    return Outcome::None;
                }
                self.sync.running_storage = None;
                let reload = match result {
                    Ok(outcome) => {
                        self.sync
                            .servers
                            .entry(storage_id.clone())
                            .or_default()
                            .failure = None;
                        outcome.changes_committed > 0 || outcome.vaults_reconciled > 0
                    }
                    Err(failure) => {
                        self.sync
                            .servers
                            .entry(storage_id.clone())
                            .or_default()
                            .failure = Some(failure);
                        false
                    }
                };
                let mut tasks = vec![
                    self.arm_auto_sync(session),
                    self.load_sync_state(session, storage_id.clone()),
                ];
                if reload
                    && self.selected_storage_id() == Some(storage_id.as_str())
                    && list_generation == self.list_generation
                    && !self.busy
                    && !self.searching
                    && self.editor.is_none()
                    && self.history.is_none()
                {
                    let facade = session.facade();
                    let query =
                        (!self.applied_query.is_empty()).then(|| self.applied_query.clone());
                    tasks.push(cosmic::task::future(async move {
                        let result = off_thread(move || {
                            let context = local::vault_context(&facade)?;
                            Ok((context, local::items(&facade, None, query)?))
                        })
                        .await;
                        Message::SyncedWorkspaceLoaded {
                            storage_id,
                            list_generation,
                            result,
                        }
                    }));
                }
                Outcome::Task(Task::batch(tasks))
            }
            Message::SyncedWorkspaceLoaded {
                storage_id,
                list_generation,
                result,
            } => {
                if self.selected_storage_id() != Some(storage_id.as_str())
                    || self.list_generation != list_generation
                    || self.switching_context
                    || self.busy
                    || self.searching
                    || self.editor.is_some()
                    || self.history.is_some()
                {
                    return Outcome::None;
                }
                match result {
                    Ok((context, page))
                        if context.current_storage_id.as_deref() == Some(storage_id.as_str())
                            && context.current_vault_id == self.selected_vault_id =>
                    {
                        self.apply_context(context);
                        self.list_generation = self.list_generation.wrapping_add(1);
                        self.apply_page(page, true);
                        self.reconcile_selection();
                        self.rebuild_nav();
                        if let Some(id) = self.selected_item_id().map(str::to_owned) {
                            return Outcome::Task(self.load_detail(id, session));
                        }
                    }
                    Ok(_) => {}
                    Err(error) => self.list_error = Some(error),
                }
                Outcome::None
            }
            _ => unreachable!("only sync effects reach this handler"),
        }
    }
}
