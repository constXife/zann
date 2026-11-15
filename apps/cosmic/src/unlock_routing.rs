//! Toolkit navigation for shared unlock routes and recovery results.
use super::*;
use zann_cosmic::screens::accounts;
impl App {
    pub(super) fn show_account_recovery(&mut self) -> Task<Message> {
        let Shell::Ready { session, screen } = &mut self.shell else {
            return Task::none();
        };
        session.auto_sync().locked();
        let (state, load) = accounts::State::new(session);
        *screen = Screen::Accounts(Box::new(state));
        lift(load, Message::Accounts)
    }
    pub(super) fn update_accounts(&mut self, message: accounts::Message) -> Task<Message> {
        let outcome = match &mut self.shell {
            Shell::Ready {
                session,
                screen: Screen::Accounts(state),
            } => state.update(message, session),
            _ => return Task::none(),
        };
        match outcome {
            accounts::Outcome::None => Task::none(),
            accounts::Outcome::Task(task) => lift(task, Message::Accounts),
            accounts::Outcome::Opened(page) => self.open_unlocked_vault(page, None),
            accounts::Outcome::Unlock(storage) => {
                let Shell::Ready { session, screen } = &mut self.shell else {
                    return Task::none();
                };
                *screen = Screen::Master(Box::new(
                    master::State::new(master::Mode::Unlock, None).with_storage(storage),
                ));
                let focus = match screen {
                    Screen::Master(master) => lift(master.focus_password(), Message::Master),
                    _ => Task::none(),
                };
                Task::batch([remembered_unlock_task(session), focus])
            }
            accounts::Outcome::Connect(url) => {
                let Shell::Ready { screen, .. } = &mut self.shell else {
                    return Task::none();
                };
                let return_to = Box::new(std::mem::replace(screen, Screen::Welcome));
                *screen = Screen::Connect {
                    state: Box::new(url.map_or_else(connect::State::default, |(storage, url)| {
                        connect::State::with_replica(storage, Some(url))
                    })),
                    return_to: Some(return_to),
                };
                Task::none()
            }
        }
    }
    pub(super) fn update_master(&mut self, message: master::Message) -> Task<Message> {
        let outcome = match &mut self.shell {
            Shell::Ready {
                session,
                screen: Screen::Master(state),
            } => state.update(message, session),
            _ => return Task::none(),
        };
        match outcome {
            master::Outcome::None => Task::none(),
            master::Outcome::Task(task) => lift(task, Message::Master),
            master::Outcome::Recovery => self.show_account_recovery(),
            master::Outcome::Opened { page, sync_after } => {
                self.open_unlocked_vault(page, sync_after)
            }
        }
    }
    fn open_unlocked_vault(
        &mut self,
        page: zann_cosmic::backend::local::ItemsPage,
        sync_after: Option<String>,
    ) -> Task<Message> {
        self.last_activity = std::time::Instant::now();
        let content_width = self.content_width();
        let Shell::Ready { session, screen } = &mut self.shell else {
            return Task::none();
        };
        session
            .auto_sync()
            .unlocked(std::time::Instant::now(), false);
        let mut state = vault::State::new(page, None);
        state.set_initial_sync_target(sync_after, session.facade().current_vault_id().is_none());
        state.set_content_width(content_width);
        state.set_reveal_seconds(self.preferences.auto_hide_reveal_seconds);
        let load = state.load_vaults(session);
        let auto_sync = state.arm_auto_sync(session);
        *screen = Screen::Vault(Box::new(state));
        lift(cosmic::iced::Task::batch([load, auto_sync]), Message::Vault)
    }
}

impl App {
    fn idle_due(&self) -> bool {
        zann_flows::unlock::idle_lock_due(
            self.is_unlocked(),
            self.preferences.auto_lock_minutes,
            i64::try_from(self.last_activity.elapsed().as_millis())
                .expect("monotonic interval fits i64"),
        )
    }
    pub(super) fn check_session_idle(&mut self) -> Task<Message> {
        if self.idle_check_pending || !self.idle_due() {
            return Task::none();
        }
        let Shell::Ready { session, .. } = &self.shell else {
            return Task::none();
        };
        let facade = session.facade();
        self.idle_check_pending = true;
        cosmic::task::future(async move {
            Message::IdlePresence(
                zann_cosmic::backend::off_thread(move || {
                    facade.idle_unlock_key_present().map_err(|e| e.to_string())
                })
                .await,
            )
        })
    }
    pub(super) fn finish_idle_check(&mut self, result: Result<bool, String>) -> Task<Message> {
        self.idle_check_pending = false;
        if !self.idle_due() {
            return Task::none();
        }
        match result {
            Ok(true) => {
                self.last_activity = std::time::Instant::now();
                Task::none()
            }
            Ok(false) => self.lock(),
            Err(error) => {
                eprintln!("idle hardware presence check failed: {error}");
                self.lock()
            }
        }
    }
}
