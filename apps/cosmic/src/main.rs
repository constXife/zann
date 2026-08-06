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

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use cosmic::app::{Core, Settings, Task};
use cosmic::iced::core::layout::Limits;
use cosmic::iced::{event, keyboard, mouse, window, Event, Length, Size, Subscription};
use cosmic::prelude::*;
use cosmic::widget::{menu, nav_bar};
use cosmic::{executor, widget, Application, Element};
use zann_cosmic::backend::{self, local};
use zann_cosmic::i18n;
use zann_cosmic::screens::{self, connect, master, settings, vault, welcome, Screen};
use zann_cosmic::session::Session;
use zann_cosmic::settings::{Change, Settings as AppSettings};
use zann_cosmic::tray;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ahead of the tray, whose menu labels come from the catalogue and would
    // otherwise be built in whatever language the environment happens to ask
    // for rather than the one that was chosen.
    i18n::set_language(AppSettings::load().language.as_deref());
    let has_tray = tray::start(App::APP_ID, "zann");

    let settings = Settings::default()
        .size(WINDOW_SIZE)
        .size_limits(
            Limits::NONE
                .min_width(WINDOW_MIN.width)
                .min_height(WINDOW_MIN.height),
        )
        // Never libcosmic's call. Closing is a preference that can change while
        // the app runs, so both the header button and the compositor come back
        // as messages and the shell decides then — see `close_intent`.
        .exit_on_close(false);

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

/// How often the idle check runs. Coarse on purpose: the shortest auto-lock the
/// settings offer is a minute, so a finer tick would only burn wakeups.
const IDLE_TICK: Duration = Duration::from_secs(15);

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
    settings: AppSettings,
    /// Shown over whatever is underneath rather than replacing it, so opening
    /// the settings does not throw away the vault's list and its scroll.
    settings_screen: Option<Box<settings::State>>,
    last_activity: Instant,
    /// What we last put on the clipboard, and how many times we have put
    /// something there. A timer cannot be cancelled once handed to the runtime,
    /// so the count is what lets a stale one recognise itself and do nothing.
    clipboard: (String, u64),
}

#[derive(Clone, Debug)]
enum Message {
    Welcome(welcome::Message),
    Connect(connect::Message),
    Master(master::Message),
    Vault(vault::Message),
    Settings(settings::Message),
    /// Effects the shell owns because they leave the app.
    Copy(String),
    OpenUrl(String),
    Tray(tray::Command),
    OpenSettings,
    /// The user asked for the window to go away — from the header bar, or from
    /// the compositor. What that means is a setting.
    CloseIntent,
    /// A window is gone, whoever closed it.
    WindowClosed,
    Unfocused,
    IdleTick,
    /// Any input at all. Only for the idle clock, so it carries nothing.
    Activity,
    /// The clipboard's time is up, for the copy that was current when it
    /// started. A newer copy makes this a no-op.
    ClipboardExpired(u64),
    /// What the clipboard holds now, so a copy that is no longer ours is left
    /// alone.
    ClipboardRead(Option<String>),
}

/// What the header bar's menu can do. Separate from [`Message`] because the
/// menu matches actions against the key binds by equality, which a message
/// carrying a `String` could not do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Lock,
    Settings,
    Quit,
}

impl menu::Action for Action {
    type Message = Message;

    fn message(&self) -> Message {
        match self {
            Self::Lock => Message::Tray(tray::Command::Lock),
            Self::Settings => Message::OpenSettings,
            Self::Quit => Message::Tray(tray::Command::Quit),
        }
    }
}

/// The shortcuts, which the menu also reads to print the hint beside each item.
/// The same pair the desktop app binds, so muscle memory carries over.
fn key_binds() -> &'static HashMap<menu::KeyBind, Action> {
    static BINDS: OnceLock<HashMap<menu::KeyBind, Action>> = OnceLock::new();
    BINDS.get_or_init(|| {
        let bind = |character: &str| menu::KeyBind {
            modifiers: vec![menu::key_bind::Modifier::Ctrl],
            key: keyboard::Key::Character(character.into()),
        };
        HashMap::from([
            (bind("l"), Action::Lock),
            (bind(","), Action::Settings),
            (bind("q"), Action::Quit),
        ])
    })
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
        let settings = AppSettings::load();

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
            settings,
            settings_screen: None,
            last_activity: Instant::now(),
            clipboard: (String::new(), 0),
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
        Some(Message::CloseIntent)
    }

    /// Called once a surface is gone. Popups close too, so only the one the
    /// shell draws into counts.
    fn on_close_requested(&self, id: window::Id) -> Option<Self::Message> {
        self.core
            .main_window_is(id)
            .then_some(Message::WindowClosed)
    }

    /// COSMIC has no global menu bar; the apps keep theirs in their own header,
    /// beside the nav-bar toggle. This is that menu — everything here acts on
    /// the app rather than on whatever screen happens to be showing, which is
    /// why locking lives here and not in the item list's toolbar.
    fn header_start(&self) -> Vec<Element<'_, Self::Message>> {
        if matches!(self.shell, Shell::Blocked(_)) {
            return Vec::new();
        }

        let unlocked = self.is_unlocked();
        let lock = if unlocked {
            menu::Item::Button
        } else {
            // Nothing to lock yet, but the item stays so the menu does not
            // change shape between screens.
            menu::Item::ButtonDisabled
        }(
            i18n::t("common.lock"),
            Some(widget::icon::from_name("system-lock-screen-symbolic").handle()),
            Action::Lock,
        );

        let items = menu::items(
            key_binds(),
            vec![
                lock,
                menu::Item::Button(
                    i18n::t("common.settings"),
                    Some(widget::icon::from_name("preferences-system-symbolic").handle()),
                    Action::Settings,
                ),
                menu::Item::Divider,
                menu::Item::Button(
                    i18n::t("common.quit"),
                    Some(widget::icon::from_name("application-exit-symbolic").handle()),
                    Action::Quit,
                ),
            ],
        );

        let root = widget::button::icon(widget::icon::from_name("open-menu-symbolic"))
            .class(cosmic::theme::Button::MenuRoot)
            .apply(Element::from)
            .apply(widget::RcElementWrapper::new);

        vec![menu::bar(vec![menu::Tree::with_children(root, items)])
            .item_width(menu::ItemWidth::Uniform(240))
            .item_height(menu::ItemHeight::Uniform(36))
            .into()]
    }

    /// The nav bar belongs to the vault screen, and the settings cover it.
    fn nav_model(&self) -> Option<&nav_bar::Model> {
        if self.settings_screen.is_some() {
            return None;
        }
        match &self.shell {
            Shell::Ready {
                screen: Screen::Vault(vault),
                ..
            } => Some(vault.nav_model()),
            _ => None,
        }
    }

    /// The default nav bar is the categories and nothing else. The desktop app
    /// stacks three things in that column — which vault, the categories, the
    /// folders — and the folders cannot join the categories in one model:
    /// libcosmic's nav bar has a single selection, while a folder narrows
    /// whatever category is showing rather than replacing it.
    ///
    /// So the categories keep the stock widget and the rest is drawn around it.
    fn nav_bar(&self) -> Option<Element<'_, cosmic::Action<Message>>> {
        if !self.core.nav_bar_active() {
            return None;
        }
        let Shell::Ready {
            screen: Screen::Vault(vault),
            ..
        } = &self.shell
        else {
            return None;
        };
        if self.settings_screen.is_some() {
            return None;
        }

        let spacing = cosmic::theme::spacing();
        let categories = widget::nav_bar(vault.nav_model(), |id| {
            cosmic::Action::Cosmic(cosmic::app::Action::NavBar(id))
        });

        let mut column = widget::column::with_capacity(4).spacing(spacing.space_xs);
        if let Some(vaults) = vault.vaults_view() {
            column = column.push(vaults.map(|m| cosmic::Action::App(Message::Vault(m))));
        }
        column = column
            .push(categories)
            .push(widget::divider::horizontal::default())
            .push(
                widget::scrollable(vault.folders_view())
                    .height(Length::Fill)
                    .apply(Element::from)
                    .map(|m| cosmic::Action::App(Message::Vault(m))),
            );

        // The stock nav bar paints its own background through `into_container`,
        // which is bypassed by building the widget into a column, so the same
        // style is put back here or the sidebar comes out transparent.
        Some(
            column
                .apply(widget::container)
                .class(cosmic::theme::Container::custom(
                    cosmic::widget::nav_bar::nav_bar_style,
                ))
                .width(Length::Fixed(NAV_WIDTH - 8.0))
                .height(Length::Fill)
                .padding(spacing.space_xxs)
                .into(),
        )
    }

    fn on_nav_select(&mut self, id: nav_bar::Id) -> Task<Self::Message> {
        let Shell::Ready {
            screen: Screen::Vault(vault),
            ..
        } = &mut self.shell
        else {
            return Task::none();
        };
        vault.activate_nav(id);

        let category = vault.selected_category();
        if self
            .settings
            .remember(zann_cosmic::settings::Place::Category(category))
        {
            if let Err(err) = self.settings.save() {
                eprintln!("could not save the settings: {err}");
            }
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

        let mut subscriptions = vec![screen];

        // The header bar's close button arrives through `on_app_exit`, but a
        // close from the compositor is a plain window event once the window is
        // no longer allowed to act on one by itself. Focus is read the same
        // way; whether losing it locks is decided in `update`, because
        // `listen_with` takes a bare `fn` with nothing captured.
        subscriptions.push(event::listen_with(|event, _, _| match event {
            Event::Window(window::Event::CloseRequested) => Some(Message::CloseIntent),
            Event::Window(window::Event::Unfocused) => Some(Message::Unfocused),
            // The menu prints the shortcuts but does not listen for them, so
            // this is where they are matched. `KeyBind` falls back to the
            // physical key, which is what makes Ctrl+L work on a layout where
            // that key does not produce an `l`.
            Event::Keyboard(keyboard::Event::KeyPressed {
                ref key,
                ref physical_key,
                modifiers,
                ..
            }) => key_binds()
                .iter()
                .find(|(bind, _)| bind.matches(modifiers, key, Some(physical_key)))
                .map(|(_, action)| menu::Action::message(action)),
            _ => None,
        }));

        if self.has_tray {
            subscriptions.push(tray::subscription().map(Message::Tray));
        }

        // Idle is measured from discrete input rather than from the pointer
        // crossing the window: a mouse moved by a cat is not someone reading
        // their vault, and it would cost a redraw per motion event to believe
        // otherwise.
        if self.settings.auto_lock_minutes > 0 && self.is_unlocked() {
            subscriptions.push(event::listen_with(|event, _, _| match event {
                Event::Keyboard(keyboard::Event::KeyPressed { .. })
                | Event::Mouse(mouse::Event::ButtonPressed(_))
                | Event::Mouse(mouse::Event::WheelScrolled { .. }) => Some(Message::Activity),
                _ => None,
            }));
            subscriptions.push(cosmic::iced::time::every(IDLE_TICK).map(|_| Message::IdleTick));
        }

        Subscription::batch(subscriptions)
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        // Effects that leave the app, and the window itself, are the shell's —
        // whoever asked for them.
        match message {
            Message::Copy(value) => return self.copy(value),
            Message::OpenUrl(url) => {
                if let Err(err) = open::that_detached(&url) {
                    eprintln!("could not open: {err}");
                }
                return Task::none();
            }
            Message::CloseIntent => {
                return if self.has_tray && self.settings.close_to_tray {
                    self.hide_window()
                } else {
                    self.quit()
                };
            }
            Message::WindowClosed => {
                self.window_open = false;
                return Task::none();
            }
            Message::Unfocused => {
                return if self.settings.lock_on_focus_loss {
                    self.lock()
                } else {
                    Task::none()
                };
            }
            Message::Activity => {
                self.last_activity = Instant::now();
                return Task::none();
            }
            Message::IdleTick => {
                let idle = Duration::from_secs(u64::from(self.settings.auto_lock_minutes) * 60);
                return if self.last_activity.elapsed() >= idle {
                    self.lock()
                } else {
                    Task::none()
                };
            }
            Message::ClipboardExpired(generation) => {
                // A newer copy has replaced the one this timer was started for.
                if generation != self.clipboard.1 {
                    return Task::none();
                }
                return self.clear_clipboard();
            }
            Message::ClipboardRead(current) => {
                return if current.as_deref() == Some(self.clipboard.0.as_str()) {
                    self.wipe_clipboard()
                } else {
                    Task::none()
                };
            }
            Message::OpenSettings => return self.open_settings(),
            Message::Tray(tray::Command::Show) => return self.show_window(),
            Message::Tray(tray::Command::Settings) => {
                return Task::batch([self.show_window(), self.open_settings()]);
            }
            Message::Tray(tray::Command::Quit) => return self.quit(),
            Message::Tray(tray::Command::Lock) => return self.lock(),
            Message::Settings(message) => return self.update_settings(message),
            _ => {}
        }

        // The screens borrow `self.shell`, so losing the session is recorded
        // here and applied once that borrow ends.
        let mut lost_session = None;
        let mut moved = None;
        let content_width = self.content_width();
        let reveal_seconds = self.settings.auto_hide_reveal_seconds;
        let list_width = self.settings.list_width;
        let last_category = self.settings.last_category.clone();
        let last_category = last_category.as_deref();
        let last_folder = self.settings.last_folder.clone();
        let last_folder = last_folder.as_deref();

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
                            vault.set_reveal_seconds(reveal_seconds);
                            vault.set_vaults(
                                local::vaults(&session.facade()),
                                local::current_vault(&session.facade()),
                            );
                            vault.restore(list_width, last_category, last_folder);
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
                        vault::Outcome::Moved(place) => {
                            // Recorded here rather than saved: writing on every
                            // pixel of a drag would hammer the file.
                            moved = Some(place);
                            Task::none()
                        }
                        vault::Outcome::SwitchVault(id) => {
                            match local::switch_vault(&session.facade(), id) {
                                Ok(page) => {
                                    let vaults = local::vaults(&session.facade());
                                    let current = local::current_vault(&session.facade());
                                    let mut next = vault::State::new(page, None);
                                    next.set_content_width(content_width);
                                    next.set_reveal_seconds(reveal_seconds);
                                    next.set_vaults(vaults, current);
                                    *screen = Screen::Vault(Box::new(next));
                                }
                                Err(err) => eprintln!("could not switch the vault: {err}"),
                            }
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
        if let Some(place) = moved {
            if self.settings.remember(place) {
                if let Err(err) = self.settings.save() {
                    eprintln!("could not save the settings: {err}");
                }
            }
        }
        task
    }

    fn view(&self) -> Element<'_, Self::Message> {
        match self.settings_screen.as_ref() {
            Some(settings) => settings.view().map(Message::Settings),
            None => match &self.shell {
                Shell::Blocked(reason) => blocked_view(reason),
                Shell::Ready { screen, .. } => match screen {
                    Screen::Welcome => welcome::view().map(Message::Welcome),
                    Screen::Connect(state) => state.view().map(Message::Connect),
                    Screen::Master(state) => state.view().map(Message::Master),
                    Screen::Vault(state) => state.view().map(Message::Vault),
                },
            },
        }
    }
}

impl App {
    /// Whether there is anything worth locking. The other screens hold nothing.
    fn is_unlocked(&self) -> bool {
        matches!(
            &self.shell,
            Shell::Ready {
                screen: Screen::Vault(_),
                ..
            }
        )
    }

    fn open_settings(&mut self) -> Task<Message> {
        if self.settings_screen.is_some() {
            return Task::none();
        }
        let storages = match &self.shell {
            Shell::Ready { session, .. } => local::storages(&session.facade()).unwrap_or_default(),
            Shell::Blocked(_) => Vec::new(),
        };
        self.settings_screen = Some(Box::new(settings::State::new(
            self.settings.clone(),
            storages,
        )));
        Task::none()
    }

    fn update_settings(&mut self, message: settings::Message) -> Task<Message> {
        let Some(state) = self.settings_screen.as_mut() else {
            return Task::none();
        };
        match state.update(message) {
            settings::Outcome::None => Task::none(),
            settings::Outcome::Task(task) => lift(task, Message::Settings),
            settings::Outcome::OpenUrl(url) => cosmic::task::message(Message::OpenUrl(url)),
            settings::Outcome::Close => {
                self.settings_screen = None;
                Task::none()
            }
            settings::Outcome::AddServer => {
                self.settings_screen = None;
                if let Shell::Ready { screen, .. } = &mut self.shell {
                    *screen = Screen::Connect(Box::default());
                }
                Task::none()
            }
            settings::Outcome::Changed(change) => self.change_setting(change),
            settings::Outcome::Sync(storage_id) => {
                let Shell::Ready { session, .. } = &self.shell else {
                    return Task::none();
                };
                let facade = session.facade();
                lift(
                    cosmic::task::future(async move {
                        settings::Message::Synced(
                            backend::off_thread(move || local::sync(&facade, Some(storage_id)))
                                .await,
                        )
                    }),
                    Message::Settings,
                )
            }
        }
    }

    /// A change lands in three places: the shell's copy, the file, and the
    /// screen that drew the control — which is told rather than left to assume,
    /// so a write that failed does not show as one that worked.
    fn change_setting(&mut self, change: Change) -> Task<Message> {
        self.settings.set(change);
        if matches!(change, Change::Language(_)) {
            i18n::set_language(self.settings.language.as_deref());
            tray::refresh();
        }
        if let Err(err) = self.settings.save() {
            eprintln!("could not save the settings: {err}");
        }
        if let Some(state) = self.settings_screen.as_mut() {
            state.settings_changed(self.settings.clone());
        }
        if let Shell::Ready {
            screen: Screen::Vault(vault),
            ..
        } = &mut self.shell
        {
            vault.set_reveal_seconds(self.settings.auto_hide_reveal_seconds);
        }
        Task::none()
    }

    /// Locks the vault and shows the unlock screen, taking the clipboard with
    /// it if that is what the settings ask for.
    fn lock(&mut self) -> Task<Message> {
        let Shell::Ready {
            session,
            screen: screen @ Screen::Vault(_),
        } = &mut self.shell
        else {
            return Task::none();
        };
        session.lock();
        *screen = Screen::Master(master::State::new(master::Mode::Unlock, None));
        self.settings_screen = None;

        if self.settings.clipboard_clear_on_lock {
            self.clear_clipboard()
        } else {
            Task::none()
        }
    }

    fn quit(&mut self) -> Task<Message> {
        if self.settings.clipboard_clear_on_exit {
            // The clear has to land before the runtime stops, so it is chained
            // rather than left as a task the exit would outrun.
            return self.wipe_clipboard().chain(cosmic::iced::exit());
        }
        cosmic::iced::exit()
    }

    /// Puts a secret on the clipboard and starts its clock. There is no
    /// cancelling a task already handed to the runtime, so a later copy is
    /// recognised by the count rather than by stopping the earlier timer.
    fn copy(&mut self, value: String) -> Task<Message> {
        self.clipboard.0 = value.clone();
        self.clipboard.1 += 1;
        let generation = self.clipboard.1;
        let write = cosmic::iced::clipboard::write(value);

        let seconds = u64::from(self.settings.clipboard_clear_seconds);
        if seconds == 0 {
            return write;
        }
        Task::batch([
            write,
            cosmic::task::future(async move {
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                Message::ClipboardExpired(generation)
            }),
        ])
    }

    /// Takes back what we put there — but only ours, if the settings say so.
    /// Reading first costs a round trip through the runtime, which is why the
    /// answer comes back as a message.
    fn clear_clipboard(&mut self) -> Task<Message> {
        if self.clipboard.0.is_empty() {
            return Task::none();
        }
        if self.settings.clipboard_clear_if_unchanged {
            return cosmic::iced::clipboard::read()
                .map(|value| cosmic::Action::App(Message::ClipboardRead(value)));
        }
        self.wipe_clipboard()
    }

    fn wipe_clipboard(&mut self) -> Task<Message> {
        self.clipboard.0.clear();
        cosmic::iced::clipboard::write(String::new())
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
        let lock = if self.settings.lock_on_hidden {
            self.lock()
        } else {
            Task::none()
        };
        Task::batch([lock, window::close(id)])
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
