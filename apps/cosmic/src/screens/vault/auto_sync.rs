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
        let storage_id = self
            .workspace
            .storage_id
            .clone()
            .or_else(|| self.progress.initial_target.clone());
        self.sync.running_storage = storage_id.clone();
        self.progress.run = crate::backend::next_view_request();
        self.progress.refreshing = false;
        self.progress.pending = false;
        self.progress.failure = None;
        self.progress.running = true;
        super::sync_progress::sync_task(
            session.facade(),
            ticket,
            storage_id,
            self.list_generation,
            self.progress.run,
        )
    }

    pub(super) fn update_auto_sync(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::SyncDue(timer) => {
                if timer != self.sync_timer {
                    return Outcome::None;
                }
                // Context completion rearms the schedule; do not spin on an overdue timer.
                if self.switching_context {
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
                let storage_id = storage_id.or_else(|| self.sync.running_storage.clone());
                self.sync.running_storage = None;
                self.progress.running = false;
                let succeeded = result.is_ok();
                let Some(storage_id) = storage_id else {
                    if let Err(failure) = result {
                        self.progress.failure = Some(failure.to_string());
                    }
                    let refresh = if succeeded {
                        self.queue_committed_refresh(session)
                    } else {
                        Task::none()
                    };
                    return Outcome::Task(Task::batch([self.arm_auto_sync(session), refresh]));
                };
                let reload = match result {
                    Ok(outcome) => {
                        self.sync
                            .servers
                            .entry(storage_id.clone())
                            .or_default()
                            .failure = None;
                        outcome.changes_committed > 0
                            || outcome.vaults_reconciled > 0
                            || self.progress.awaiting_first
                    }
                    Err(failure) => {
                        self.progress.failure = Some(failure.to_string());
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
                if succeeded && self.selected_storage_id() == Some(storage_id.as_str()) {
                    tasks.push(self.refresh_history(session));
                }
                if reload
                    && (self.selected_storage_id().is_none()
                        || self.selected_storage_id() == Some(storage_id.as_str()))
                    && list_generation == self.list_generation
                    && !self.busy
                    && !self.searching
                    && self.editor.is_none()
                    && self.history.is_none()
                {
                    tasks.push(self.queue_committed_refresh(session));
                }

                Outcome::Task(Task::batch(tasks))
            }
            _ => unreachable!("only sync effects reach this handler"),
        }
    }
}
