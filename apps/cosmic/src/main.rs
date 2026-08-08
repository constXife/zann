// SPDX-License-Identifier: MIT

//! COSMIC-native PoC for zann.
//!
//! It connects to a server (or sets up a local vault), unlocks it with the
//! master password, browses the items and reads a secret. Every rule that
//! decides *what* is shown — the nav
//! categories, the client-side filter — comes from `zann-ui-core`, so this app
//! only owns its widgets.
//!
//! This file is the shell and nothing else: it owns the window, the
//! [`Session`], and the routing between screens. Each screen in [`screens`]
//! owns its own state and messages and reports back through its `Outcome`.

use cosmic::app::{Core, Settings, Task};
use cosmic::iced::{Size, Subscription};
use cosmic::prelude::*;
use cosmic::widget::nav_bar;
use cosmic::{executor, Element};
use zann_cosmic::screens::{self, connect, master, settings, vault, welcome, Screen};
use zann_cosmic::session::Session;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::default().size(Size::new(1000.0, 700.0));
    cosmic::app::run::<App>(settings, ())?;
    Ok(())
}

/// Either the local database opened and the app has a session, or it did not
/// and there is nothing to show. Modelling it this way is what keeps every
/// screen free of `Option<Facade>`.
enum Shell {
    Blocked(String),
    Ready { session: Session, screen: Screen },
}

struct App {
    core: Core,
    shell: Shell,
}

#[derive(Clone, Debug)]
enum Message {
    Welcome(welcome::Message),
    Connect(connect::Message),
    Master(master::Message),
    Settings(settings::Message),
    Vault(vault::Message),
    /// Effects the shell owns because they leave the app.
    Copy(String),
    OpenUrl(String),
}

/// Lifts a screen's task into the shell's message type.
fn lift<M: Send + 'static>(task: cosmic::iced::Task<M>, wrap: fn(M) -> Message) -> Task<Message> {
    task.map(move |message| cosmic::Action::App(wrap(message)))
}

impl cosmic::Application for App {
    type Executor = executor::Default;
    type Flags = ();
    type Message = Message;

    /// Matches `StartupWMClass` in `data/com.rlyeh.zann.Cosmic.desktop`, which
    /// is how the compositor ties the window to the launcher entry, and shares
    /// the prefix the Tauri app already uses (`com.rlyeh.zann`).
    const APP_ID: &'static str = "com.rlyeh.zann.Cosmic";

    fn core(&self) -> &Core {
        &self.core
    }

    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Self::Message>) {
        let shell = match Session::open() {
            Ok((session, status)) => {
                let screen = if status.initialized {
                    Screen::Master(master::State::new(master::Mode::Unlock, None))
                } else if status.storages_count > 0 {
                    // A server login already happened but the vault was never
                    // created — finish where that left off.
                    Screen::Master(master::State::new(master::Mode::Create, None))
                } else {
                    Screen::Welcome
                };
                Shell::Ready { session, screen }
            }
            Err(err) => Shell::Blocked(err),
        };

        let mut app = App { core, shell };
        app.set_header_title("zann".to_string());
        let mut task = match app.core.main_window_id() {
            Some(id) => app.set_window_title("zann".to_string(), id),
            None => Task::none(),
        };

        if let Shell::Ready {
            session,
            screen: Screen::Master(_),
        } = &app.shell
        {
            let facade = session.facade();
            task = Task::batch([
                task,
                cosmic::task::future(async move {
                    zann_cosmic::backend::off_thread(move || {
                        zann_cosmic::backend::local::remembered_unlock(&facade)
                    })
                    .await
                })
                .map(|remembered: Result<_, String>| match remembered {
                    Ok(remembered) => cosmic::Action::App(Message::Master(
                        master::Message::Remembered(remembered),
                    )),
                    // Nothing remembered, or nothing readable: the password
                    // path is always there, so this is not worth a banner.
                    Err(_) => cosmic::Action::None,
                }),
            ]);
        }

        (app, task)
    }

    /// The nav bar belongs to the vault screen.
    fn nav_model(&self) -> Option<&nav_bar::Model> {
        match &self.shell {
            Shell::Ready {
                screen: Screen::Vault(vault),
                ..
            } => Some(vault.nav_model()),
            _ => None,
        }
    }

    fn on_nav_select(&mut self, id: nav_bar::Id) -> Task<Self::Message> {
        if let Shell::Ready {
            screen: Screen::Vault(vault),
            ..
        } = &mut self.shell
        {
            vault.activate_nav(id);
        }
        Task::none()
    }

    fn context_drawer(&self) -> Option<cosmic::app::context_drawer::ContextDrawer<'_, Message>> {
        match &self.shell {
            Shell::Ready {
                screen: Screen::Vault(vault),
                ..
            } => vault
                .context_drawer()
                .map(|drawer| drawer.map(Message::Vault)),
            _ => None,
        }
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        match &self.shell {
            Shell::Ready {
                screen: Screen::Connect(connect),
                ..
            } => connect.subscription().map(Message::Connect),
            Shell::Ready {
                screen: Screen::Vault(vault),
                ..
            } => vault.subscription().map(Message::Vault),
            _ => Subscription::none(),
        }
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        // Effects that leave the app are the shell's, whoever asked for them.
        match message {
            Message::Copy(value) => return cosmic::iced::clipboard::write(value),
            Message::OpenUrl(url) => {
                if let Err(err) = open::that_detached(&url) {
                    eprintln!("could not open the browser: {err}");
                }
                return Task::none();
            }
            _ => {}
        }

        // The screens borrow `self.shell`, so losing the session is recorded
        // here and applied once that borrow ends.
        let mut lost_session = None;

        let task = {
            let Shell::Ready { session, screen } = &mut self.shell else {
                return Task::none();
            };

            // Each arm reborrows the screen just long enough to run its
            // update, so the transition afterwards is free to replace it.
            match message {
                Message::Welcome(message) => {
                    if !matches!(screen, Screen::Welcome) {
                        return Task::none();
                    }
                    *screen = match message {
                        welcome::Message::UseLocalVault => {
                            Screen::Master(master::State::new(master::Mode::Create, None))
                        }
                        welcome::Message::ConnectToServer => Screen::Connect(Box::default()),
                    };
                    Task::none()
                }

                Message::Connect(message) => {
                    let Screen::Connect(state) = &mut *screen else {
                        return Task::none();
                    };
                    match state.update(message) {
                        connect::Outcome::None => Task::none(),
                        connect::Outcome::Task(task) => lift(task, Message::Connect),
                        connect::Outcome::Copy(value) => {
                            cosmic::task::message(Message::Copy(value))
                        }
                        connect::Outcome::OpenUrl(url) => {
                            cosmic::task::message(Message::OpenUrl(url))
                        }
                        connect::Outcome::Cancelled => {
                            *screen = Screen::Welcome;
                            Task::none()
                        }
                        connect::Outcome::Connected {
                            storage_id,
                            has_personal_keys,
                        } => {
                            // The login rewrote the identity config, so the
                            // session has to be rebuilt from it before the
                            // vault is opened.
                            match session.reload() {
                                Ok(()) => {
                                    let mode = if has_personal_keys {
                                        master::Mode::Unlock
                                    } else {
                                        master::Mode::Create
                                    };
                                    *screen =
                                        Screen::Master(master::State::new(mode, Some(storage_id)));
                                }
                                Err(err) => lost_session = Some(err),
                            }
                            Task::none()
                        }
                    }
                }

                Message::Master(message) => {
                    let Screen::Master(state) = &mut *screen else {
                        return Task::none();
                    };
                    match state.update(message, session) {
                        master::Outcome::None => Task::none(),
                        master::Outcome::Task(task) => lift(task, Message::Master),
                        master::Outcome::Opened { page, sync_error } => {
                            *screen = Screen::Vault(Box::new(vault::State::new(page, sync_error)));
                            Task::none()
                        }
                    }
                }

                Message::Settings(message) => {
                    let Screen::Settings { state, .. } = &mut *screen else {
                        return Task::none();
                    };
                    match state.update(message, session) {
                        settings::Outcome::None => Task::none(),
                        settings::Outcome::Task(task) => lift(task, Message::Settings),
                        settings::Outcome::Close => {
                            // Take the vault back out of the screen it was
                            // parked in; `replace` keeps this a move.
                            let parked = std::mem::replace(&mut *screen, Screen::Welcome);
                            if let Screen::Settings { vault, .. } = parked {
                                *screen = Screen::Vault(vault);
                            }
                            Task::none()
                        }
                    }
                }

                Message::Vault(message) => {
                    let Screen::Vault(state) = &mut *screen else {
                        return Task::none();
                    };
                    match state.update(message, session) {
                        vault::Outcome::None => Task::none(),
                        vault::Outcome::Task(task) => lift(task, Message::Vault),
                        vault::Outcome::Copy(value) => cosmic::task::message(Message::Copy(value)),
                        vault::Outcome::ShowDetail(show) => {
                            self.core.set_show_context(show);
                            Task::none()
                        }
                        vault::Outcome::Locked => {
                            self.core.set_show_context(false);
                            *screen =
                                Screen::Master(master::State::new(master::Mode::Unlock, None));
                            Task::none()
                        }
                        vault::Outcome::OpenSettings => {
                            self.core.set_show_context(false);
                            let load = settings::State::load(session);
                            let parked = std::mem::replace(&mut *screen, Screen::Welcome);
                            if let Screen::Vault(vault) = parked {
                                *screen = Screen::Settings {
                                    state: settings::State::new(),
                                    vault,
                                };
                            }
                            lift(load, Message::Settings)
                        }
                    }
                }

                // Handled above, before the session was borrowed.
                Message::Copy(_) | Message::OpenUrl(_) => Task::none(),
            }
        };

        if let Some(err) = lost_session {
            self.shell = Shell::Blocked(err);
        }
        task
    }

    fn view(&self) -> Element<'_, Self::Message> {
        match &self.shell {
            Shell::Blocked(reason) => blocked_view(reason),
            Shell::Ready { screen, .. } => match screen {
                Screen::Welcome => welcome::view().map(Message::Welcome),
                Screen::Connect(state) => state.view().map(Message::Connect),
                Screen::Master(state) => state.view().map(Message::Master),
                Screen::Vault(state) => state.view().map(Message::Vault),
                Screen::Settings { state, .. } => state.view().map(Message::Settings),
            },
        }
    }
}

fn blocked_view(reason: &str) -> Element<'_, Message> {
    use cosmic::iced::Alignment;
    use cosmic::{theme, widget};

    let spacing = theme::spacing();
    screens::centered(
        widget::column::with_capacity(2)
            .push(widget::text::title3("zann"))
            .push(widget::text::body(reason.to_string()))
            .spacing(spacing.space_s)
            .align_x(Alignment::Center),
    )
}
