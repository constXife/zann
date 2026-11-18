//! Executes screen effects immediately after their scoped event was accepted.
use super::*;
impl App {
    pub(super) fn update_connect(&mut self, event: connect::Event) -> Task<Message> {
        let outcomes = match &mut self.shell {
            Shell::Ready {
                screen: Screen::Connect { state, .. },
                session,
                ..
            } => {
                state.attach_browser(session.browser_control());
                state.update(event)
            }
            _ => return Task::none(),
        };
        let mut tasks = Vec::new();
        for outcome in outcomes {
            match outcome {
                connect::Outcome::Task(task) => tasks.push(lift(task, Message::Connect)),
                connect::Outcome::Copy(value) => tasks.push(self.copy(value)),
                connect::Outcome::OpenUrl(url) => {
                    if let Err(error) = open::that_detached(&url) {
                        eprintln!("could not open Connect authorization URL: {error}");
                    }
                }
                connect::Outcome::Cancelled => {
                    if let Shell::Ready { screen, .. } = &mut self.shell {
                        if let Screen::Connect { return_to, .. } = screen {
                            *screen = return_to.take().map_or(Screen::Welcome, |screen| *screen);
                        }
                    }
                }
                connect::Outcome::Connected {
                    storage_id,
                    has_personal_keys,
                    passkey,
                } => {
                    if let Shell::Ready {
                        screen, session, ..
                    } = &mut self.shell
                    {
                        let status = match session.facade().app_status() {
                            Ok(status) => status,
                            Err(error) => {
                                self.shell = Shell::Blocked(error.to_string());
                                return Task::none();
                            }
                        };
                        let mode = zann_flows::unlock::device_phase(status.initialized);
                        let mut master = master::State::new(mode, Some(storage_id.clone()))
                            .with_account(has_personal_keys)
                            .with_passkey(passkey.map(|bootstrap| *bootstrap));
                        match session.facade().setup_accounts() {
                            Ok(accounts) => {
                                if let Some(account) = accounts
                                    .into_iter()
                                    .find(|account| account.location.storage_id == storage_id)
                                {
                                    let label = match account.location.account_name {
                                        Some(name) => {
                                            format!("{} · {}", name, account.location.server_url)
                                        }
                                        None => account.location.server_url,
                                    };
                                    master = master.with_account_label(label);
                                }
                            }
                            Err(error) => {
                                self.shell = Shell::Blocked(error.to_string());
                                return Task::none();
                            }
                        }
                        if status.initialized && !status.locked {
                            if let master::Outcome::Task(task) =
                                master.update(master::Message::UseUnlocked, session)
                            {
                                tasks.push(lift(task, Message::Master));
                            }
                        }
                        tasks.push(lift(master.focus_password(), Message::Master));
                        *screen = Screen::Master(Box::new(master));
                    }
                }
            }
        }
        Task::batch(tasks)
    }
}
