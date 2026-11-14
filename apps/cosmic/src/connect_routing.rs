//! Executes screen effects immediately after their scoped event was accepted.
use super::*;
impl App {
    pub(super) fn update_connect(&mut self, event: connect::Event) -> Task<Message> {
        let outcomes = match &mut self.shell {
            Shell::Ready {
                screen: Screen::Connect { state, .. },
                ..
            } => state.update(event),
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
                } => {
                    if let Shell::Ready {
                        screen, session, ..
                    } = &mut self.shell
                    {
                        let initialized = match session.facade().app_status() {
                            Ok(status) => status.initialized,
                            Err(error) => {
                                self.shell = Shell::Blocked(error.to_string());
                                return Task::none();
                            }
                        };
                        let mode = if initialized {
                            master::Mode::Unlock
                        } else {
                            master::Mode::Create
                        };
                        *screen = Screen::Master(Box::new(
                            master::State::new(mode, Some(storage_id))
                                .with_account(has_personal_keys),
                        ));
                    }
                }
            }
        }
        Task::batch(tasks)
    }
}
