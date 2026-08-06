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
use cosmic::iced::core::layout::Limits;
use cosmic::iced::{event, window, Event, Size, Subscription};
use cosmic::prelude::*;
use cosmic::widget::nav_bar;
use cosmic::{executor, Application, Element};
use zann_cosmic::screens::{self, connect, master, vault, welcome, Screen};
use zann_cosmic::session::Session;
use zann_cosmic::tray;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Held for the whole run: dropping this takes the icon down with it.
    let has_tray = tray::start(App::APP_ID, "zann");

    let settings = Settings::default()
        .size(WINDOW_SIZE)
        .size_limits(
            Limits::NONE
                .min_width(WINDOW_MIN.width)
                .min_height(WINDOW_MIN.height),
        )
        // Without a tray the window has nowhere to go and no way back, so the
        // close button has to keep meaning what it says.
        .exit_on_close(!has_tray);

    cosmic::app::run::<App>(settings, has_tray)?;
    Ok(())
}

/// Either the local database opened and the app has a session, or it did not
/// and there is nothing to show. Modelling it this way is what keeps every
/// screen free of `Option<Facade>`.
enum Shell {
    Blocked(String),
    Ready { session: Session, screen: Screen },
}

/// What libcosmic reserves for the nav bar: 280px plus the 8px of padding it
/// puts beside it. The same pair drives its own condensed-layout breakpoint.
const NAV_WIDTH: f32 = 288.0;

/// Matches the Tauri app's window, whose minimum is the width at which its
/// three columns still hold their own minimums.
const WINDOW_SIZE: Size = Size::new(1200.0, 700.0);
const WINDOW_MIN: Size = Size::new(1125.0, 650.0);

struct App {
    core: Core,
    shell: Shell,
    window_width: f32,
    /// Whether there is a tray to hide into. Without one the close button is
    /// left alone and none of the hiding below ever runs.
    has_tray: bool,
    /// Wayland cannot unmap a window and map it back, so hiding destroys it and
    /// showing builds a new one. This is what says which of the two it is.
    window_open: bool,
}

#[derive(Clone, Debug)]
enum Message {
    Welcome(welcome::Message),
    Connect(connect::Message),
    Master(master::Message),
    Vault(vault::Message),
    /// Effects the shell owns because they leave the app.
    Copy(String),
    OpenUrl(String),
    Tray(tray::Command),
    /// The user asked for the window to go away — from the header bar, or from
    /// the compositor.
    HideWindow,
    /// A window is gone, whoever closed it.
    WindowClosed,
}

/// Lifts a screen's task into the shell's message type.
fn lift<M: Send + 'static>(task: cosmic::iced::Task<M>, wrap: fn(M) -> Message) -> Task<Message> {
    task.map(move |message| cosmic::Action::App(wrap(message)))
}

impl cosmic::Application for App {
    type Executor = executor::Default;
    /// Whether a tray icon went up, which is the one thing about the outside
    /// world the shell has to be told before it draws anything.
    type Flags = bool;
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

    fn init(core: Core, has_tray: Self::Flags) -> (Self, Task<Self::Message>) {
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

        let mut app = App {
            core,
            shell,
            window_width: WINDOW_SIZE.width,
            has_tray,
            window_open: true,
        };
        app.set_header_title("zann".to_string());
        let task = match app.core.main_window_id() {
            Some(id) => app.set_window_title("zann".to_string(), id),
            None => Task::none(),
        };
        (app, task)
    }

    /// The header bar's close button. Returning a message is what stops
    /// libcosmic from closing the window itself, so the shell gets to decide.
    fn on_app_exit(&mut self) -> Option<Self::Message> {
        self.has_tray.then_some(Message::HideWindow)
    }

    /// Called once a surface is gone. Popups close too, so only the one the
    /// shell draws into counts.
    fn on_close_requested(&self, id: window::Id) -> Option<Self::Message> {
        self.core
            .main_window_is(id)
            .then_some(Message::WindowClosed)
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

    /// The vault lays its two columns out itself, so it has to be told how much
    /// of the window the nav bar left it.
    fn on_window_resize(&mut self, _id: cosmic::iced::window::Id, width: f32, _height: f32) {
        self.window_width = width;
        let content_width = self.content_width();
        if let Shell::Ready {
            screen: Screen::Vault(vault),
            ..
        } = &mut self.shell
        {
            vault.set_content_width(content_width);
        }
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        let screen = match &self.shell {
            Shell::Ready {
                screen: Screen::Connect(connect),
                ..
            } => connect.subscription().map(Message::Connect),
            Shell::Ready {
                screen: Screen::Vault(vault),
                ..
            } => vault.subscription().map(Message::Vault),
            _ => Subscription::none(),
        };

        if !self.has_tray {
            return screen;
        }

        // The header bar's close button arrives through `on_app_exit`, but a
        // close from the compositor is a plain window event once the window is
        // no longer allowed to act on one by itself.
        let close = event::listen_with(|event, _, _| {
            matches!(event, Event::Window(window::Event::CloseRequested))
                .then_some(Message::HideWindow)
        });

        Subscription::batch([screen, close, tray::subscription().map(Message::Tray)])
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
            Message::HideWindow => return self.hide_window(),
            Message::WindowClosed => {
                self.window_open = false;
                return Task::none();
            }
            Message::Tray(tray::Command::Show) => return self.show_window(),
            Message::Tray(tray::Command::Quit) => return cosmic::iced::exit(),
            Message::Tray(tray::Command::Lock) => {
                // Only the open vault holds anything worth locking; the other
                // screens have nothing to take away.
                if let Shell::Ready {
                    session,
                    screen: screen @ Screen::Vault(_),
                } = &mut self.shell
                {
                    session.lock();
                    *screen = Screen::Master(master::State::new(master::Mode::Unlock, None));
                }
                return Task::none();
            }
            _ => {}
        }

        // The screens borrow `self.shell`, so losing the session is recorded
        // here and applied once that borrow ends.
        let mut lost_session = None;
        let content_width = self.content_width();

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
                            let mut vault = vault::State::new(page, sync_error);
                            vault.set_content_width(content_width);
                            *screen = Screen::Vault(Box::new(vault));
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
                        vault::Outcome::Locked => {
                            *screen =
                                Screen::Master(master::State::new(master::Mode::Unlock, None));
                            Task::none()
                        }
                    }
                }

                // Handled above, before the session was borrowed.
                _ => Task::none(),
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
            },
        }
    }
}

impl App {
    /// Into the tray. There is no hiding a window on Wayland — winit says as
    /// much — so this destroys it. Nothing is lost with it: every bit of state
    /// the app has, including the open [`Session`], lives in `App`.
    ///
    /// The process survives with no windows because libcosmic runs as an iced
    /// daemon, and `exit_on_close(false)` is what stops it exiting anyway.
    fn hide_window(&mut self) -> Task<Message> {
        let Some(id) = self.core.main_window_id().filter(|_| self.window_open) else {
            return Task::none();
        };
        window::close(id)
    }

    /// Back out of it, into a new window that the shell then treats as its main
    /// one — set before the task runs, because libcosmic routes anything that
    /// is not the main window to `view_window`, which this app does not have.
    fn show_window(&mut self) -> Task<Message> {
        if let Some(id) = self.core.main_window_id().filter(|_| self.window_open) {
            return cosmic::iced::window::gain_focus(id);
        }

        let (id, task) = window::open(window_settings());
        self.core.set_main_window_id(Some(id));
        self.window_open = true;
        let title = self.set_window_title("zann".to_string(), id);
        Task::batch([task.discard(), title])
    }

    /// What is left of the window once the nav bar has taken its share — which
    /// is nothing when the user has collapsed it from the header bar.
    fn content_width(&self) -> f32 {
        if self.core.nav_bar_active() {
            self.window_width - NAV_WIDTH
        } else {
            self.window_width
        }
    }
}

/// The window libcosmic would have opened at startup. It builds these from its
/// own [`Settings`] and keeps them, so reopening has to say the same things
/// again — client-side decorations above all, or the second window comes up
/// with the compositor's title bar bolted onto the app's own.
fn window_settings() -> window::Settings {
    let mut settings = window::Settings {
        size: WINDOW_SIZE,
        min_size: Some(WINDOW_MIN),
        decorations: false,
        transparent: true,
        resizable: true,
        resize_border: 8,
        // The whole point of hiding: closing this one must not end the app.
        exit_on_close_request: false,
        ..Default::default()
    };
    settings.platform_specific.application_id = App::APP_ID.to_string();
    settings
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
