//! Automatic sync of the open vault. The core's schedule, kept by the session,
//! decides when; this screen keeps a timer armed for it, runs the sync and
//! shows what it brought in.
use zann_client::app::local::AUTO_SYNC_DEBOUNCE;

use super::*;

impl State {
    /// Arms a timer for the schedule's next sync. While a sync runs nothing
    /// is due, so the timer looks again after the debounce; there is always
    /// one live timer while the vault is open, parked behind Settings too.
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

    /// A local write committed: the schedule pushes it shortly.
    pub(super) fn local_change(&mut self, session: &Session) -> Task<Message> {
        session.auto_sync().local_change(Instant::now());
        self.arm_auto_sync(session)
    }

    pub(super) fn update_auto_sync(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::SyncDue(timer) => {
                if timer != self.sync_timer {
                    return Outcome::None;
                }
                let Some(ticket) = session.auto_sync().take_due(Instant::now()) else {
                    return Outcome::Task(self.arm_auto_sync(session));
                };
                let facade = session.facade();
                let storage_id = local::current_storage_id(&facade);
                let list_generation = self.list_generation;
                let query = (!self.applied_query.is_empty()).then(|| self.applied_query.clone());
                return Outcome::Task(cosmic::task::future(async move {
                    let synced = storage_id.clone();
                    let result =
                        off_thread(move || Ok(local::sync_and_reload(&facade, synced, query)))
                            .await
                            .unwrap_or_else(|err| Err(local::SyncFailure::Other(err)));
                    Message::AutoSynced {
                        ticket,
                        storage_id,
                        list_generation,
                        result,
                    }
                }));
            }

            Message::AutoSynced {
                ticket,
                storage_id,
                list_generation,
                result,
            } => {
                if !session.auto_sync().finished(ticket, Instant::now()) {
                    // Started before a lock; this vault never asked for it.
                    return Outcome::None;
                }
                let arm = self.arm_auto_sync(session);
                let page = match result {
                    Ok(page) => {
                        if self.error.is_some() && self.error == self.sync_error {
                            self.error = None;
                        }
                        self.sync_error = None;
                        self.stale_server = None;
                        page
                    }
                    Err(failure) => {
                        let message =
                            t_args("items.syncFailed", &[("error", &failure.to_string())]);
                        self.error = Some(message.clone());
                        self.sync_error = Some(message);
                        self.stale_server = matches!(
                            failure,
                            local::SyncFailure::IdentityChanged
                                | local::SyncFailure::Disconnected { .. }
                        )
                        .then(|| (storage_id, failure));
                        None
                    }
                };
                // A newer search or a page load in flight answers for the list
                // itself; replacing it here would show an older query's page.
                let Some(page) = page.filter(|_| {
                    list_generation == self.list_generation && !self.busy && !self.searching
                }) else {
                    return Outcome::Task(arm);
                };
                self.list_generation = self.list_generation.wrapping_add(1);
                self.apply_page(page, true);
                self.rebuild_nav();
                return Outcome::Task(Task::batch([
                    arm,
                    self.refresh_detail(session),
                    Self::load_vaults(session),
                ]));
            }

            // Settings owns the recovery, the same one its own sync offers.
            Message::ReviewStaleServer => {
                if let Some((storage_id, failure)) = self.stale_server_banner() {
                    return Outcome::StaleServer(storage_id.clone(), failure.clone());
                }
            }

            Message::DetailRefreshed(Ok(detail)) => {
                let shown = self
                    .detail
                    .as_ref()
                    .is_some_and(|shown| shown.id == detail.id);
                if shown && self.editor.is_none() && self.history.is_none() {
                    self.detail = Some(detail);
                }
            }

            Message::DetailRefreshed(Err(err)) => self.error = Some(err),

            _ => unreachable!("only auto-sync messages reach this handler"),
        }
        Outcome::None
    }

    /// The stale server, while the banner its refusal left is still shown.
    pub(super) fn stale_server_banner(&self) -> Option<&(String, local::SyncFailure)> {
        self.stale_server
            .as_ref()
            .filter(|_| self.error.is_some() && self.error == self.sync_error)
    }

    /// The item on screen may have changed on the server. An open editor or
    /// history keeps what it shows.
    fn refresh_detail(&self, session: &Session) -> Task<Message> {
        let Some(id) = self.detail.as_ref().map(|detail| detail.id.clone()) else {
            return Task::none();
        };
        if self.editor.is_some() || self.history.is_some() {
            return Task::none();
        }
        let facade = session.facade();
        cosmic::task::future(async move {
            Message::DetailRefreshed(
                off_thread(move || local::item_get(&facade, id).and_then(Detail::parse)).await,
            )
        })
    }
}
