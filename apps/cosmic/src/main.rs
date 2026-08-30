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

use cosmic::app::{Core, Settings, Task};
use cosmic::iced::core::layout::Limits;
use cosmic::iced::{event, keyboard, mouse, window, Event, Length, Size, Subscription};
use cosmic::prelude::*;
use cosmic::widget::{menu, nav_bar};
use cosmic::{executor, widget, Element};
use zann_cosmic::i18n::t;
use zann_cosmic::preferences::{self, Store};
use zann_cosmic::screens::{self, connect, master, settings, vault, welcome, Screen};
use zann_cosmic::session::Session;
use zann_ui_core::DevicePreferences;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::default().size(WINDOW_SIZE).size_limits(
        Limits::NONE
            .min_width(WINDOW_MIN.width)
            .min_height(WINDOW_MIN.height),
    );
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

/// What libcosmic reserves for its navigation column, including its adjacent
/// padding. The same value drives libcosmic's condensed-layout breakpoint.
const NAV_WIDTH: f32 = 288.0;

/// Match the Tauri window and the minimum at which its three panels remain
/// useful (`apps/desktop/src-tauri/tauri.conf.json`).
const WINDOW_SIZE: Size = Size::new(1200.0, 700.0);
const WINDOW_MIN: Size = Size::new(1125.0, 650.0);

struct App {
    core: Core,
    shell: Shell,
    window_width: f32,
    preferences: DevicePreferences,
    preference_store: Option<Store>,
    /// The last secret copied and its generation, so expired timers cannot
    /// clear a newer copy.
    clipboard: (String, u64),
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
    Lock,
    OpenSettings,
    Quit,
    Unfocused,
    TemporaryReveal(bool),
    Activity,
    ClipboardExpired(u64),
    ClipboardRead(Option<String>),
}

/// Commands in the native header menu. Keeping these separate from messages
/// lets libcosmic pair them with their keyboard shortcuts.
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
            Self::Lock => Message::Lock,
            Self::Settings => Message::OpenSettings,
            Self::Quit => Message::Quit,
        }
    }
}

/// Match the shortcuts used by the Tauri app. The menu reads this same map to
/// print the shortcut beside each command.
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

/// Option is conventional on macOS and does not participate in application
/// switching there. Alt does participate in switching on Linux and Windows,
/// so those platforms use Shift for hold-to-reveal instead.
fn temporary_reveal_key() -> keyboard::Key {
    #[cfg(target_os = "macos")]
    let named = keyboard::key::Named::Alt;
    #[cfg(not(target_os = "macos"))]
    let named = keyboard::key::Named::Shift;
    keyboard::Key::Named(named)
}

/// Lifts a screen's task into the shell's message type.
fn lift<M: Send + 'static>(task: cosmic::iced::Task<M>, wrap: fn(M) -> Message) -> Task<Message> {
    task.map(move |message| cosmic::Action::App(wrap(message)))
}

/// Reload the device's unlock source whenever an unlock screen is created.
/// Startup and an explicit in-app lock must offer the same hardware-key or
/// keystore path.
fn remembered_unlock_task(session: &Session) -> Task<Message> {
    let facade = session.facade();
    cosmic::task::future(async move {
        zann_cosmic::backend::off_thread(move || {
            zann_cosmic::backend::local::remembered_unlock(&facade)
        })
        .await
    })
    .map(|remembered: Result<_, String>| match remembered {
        Ok(remembered) => {
            cosmic::Action::App(Message::Master(master::Message::Remembered(remembered)))
        }
        // The password path remains available when no remembered source can
        // be read, so this should not replace it with a blocking error.
        Err(_) => cosmic::Action::None,
    })
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

    /// App-level actions live beside the nav toggle instead of taking room
    /// from the item list. The menu stays the same shape while commands that
    /// do not apply to the current screen become disabled.
    fn header_start(&self) -> Vec<Element<'_, Self::Message>> {
        if matches!(self.shell, Shell::Blocked(_)) {
            return Vec::new();
        }

        let lock = if self.is_unlocked() {
            menu::Item::Button
        } else {
            menu::Item::ButtonDisabled
        }(
            t("common.lock"),
            Some(widget::icon::from_name("system-lock-screen-symbolic").handle()),
            Action::Lock,
        );
        let settings = if self.can_open_settings() {
            menu::Item::Button
        } else {
            menu::Item::ButtonDisabled
        }(
            t("common.settings"),
            Some(widget::icon::from_name("preferences-system-symbolic").handle()),
            Action::Settings,
        );
        let items = menu::items(
            key_binds(),
            vec![
                lock,
                settings,
                menu::Item::Divider,
                menu::Item::Button(
                    t("common.quit"),
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

    fn init(core: Core, _flags: Self::Flags) -> (Self, Task<Self::Message>) {
        let (shell, preference_store, preferences) = match Session::open() {
            Ok((session, status)) => {
                let store = Store::new(session.database_location().client_root());
                let preferences = store.load();
                let screen = if status.initialized {
                    Screen::Master(Box::new(master::State::new(master::Mode::Unlock, None)))
                } else if status.storages_count > 0 {
                    // A server login already happened but the vault was never
                    // created — finish where that left off.
                    Screen::Master(Box::new(master::State::new(master::Mode::Create, None)))
                } else {
                    Screen::Welcome
                };
                (Shell::Ready { session, screen }, Some(store), preferences)
            }
            Err(err) => (Shell::Blocked(err), None, DevicePreferences::default()),
        };

        zann_cosmic::i18n::set_language(preferences.language.as_deref());

        let mut app = App {
            core,
            shell,
            window_width: WINDOW_SIZE.width,
            preferences,
            preference_store,
            clipboard: (String::new(), 0),
        };
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
            task = Task::batch([task, remembered_unlock_task(session)]);
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

    /// Keep the storage/vault context in the navigation column, matching the
    /// desktop layout contract while still using native COSMIC widgets.
    fn nav_bar(&self) -> Option<Element<'_, cosmic::Action<Self::Message>>> {
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

        let nav = widget::nav_bar(vault.nav_model(), |id| {
            cosmic::Action::Cosmic(cosmic::app::Action::NavBar(id))
        })
        .into_container()
        .width(Length::Fill)
        .height(Length::Fill);
        let mut column = widget::column::with_capacity(2);
        if let Some(selector) = vault.vault_selector() {
            column =
                column.push(selector.map(|message| cosmic::Action::App(Message::Vault(message))));
        }
        column = column.push(nav);

        Some(
            widget::container(column)
                .width(Length::Fixed(280.0))
                .height(Length::Fill)
                .class(cosmic::theme::Container::custom(
                    widget::nav_bar::nav_bar_style,
                ))
                .into(),
        )
    }

    fn on_nav_select(&mut self, id: nav_bar::Id) -> Task<Self::Message> {
        if let Shell::Ready {
            screen: Screen::Vault(vault),
            ..
        } = &mut self.shell
        {
            vault.activate_nav(id);
            if vault.category_needs_prefetch() {
                return cosmic::task::message(Message::Vault(vault::Message::LoadMore));
            }
        }
        Task::none()
    }

    /// The vault owns the list/detail split, while the shell knows how much of
    /// the window remains after libcosmic's navigation column.
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
                screen: Screen::Connect { state: connect, .. },
                ..
            } => connect.subscription().map(Message::Connect),
            Shell::Ready {
                screen: Screen::Vault(vault),
                ..
            } => vault.subscription().map(Message::Vault),
            _ => Subscription::none(),
        };

        let shell_events = event::listen_with(|event, _, _| match event {
            Event::Window(window::Event::Unfocused) => Some(Message::Unfocused),
            Event::Keyboard(keyboard::Event::KeyPressed { ref key, .. })
                if *key == temporary_reveal_key() =>
            {
                Some(Message::TemporaryReveal(true))
            }
            Event::Keyboard(keyboard::Event::KeyReleased { ref key, .. })
                if *key == temporary_reveal_key() =>
            {
                Some(Message::TemporaryReveal(false))
            }
            Event::Keyboard(keyboard::Event::KeyPressed {
                ref key,
                ref physical_key,
                modifiers,
                ..
            }) => key_binds()
                .iter()
                .find(|(bind, _)| bind.matches(modifiers, key, Some(physical_key)))
                .map_or(Some(Message::Activity), |(_, action)| {
                    Some(menu::Action::message(action))
                }),
            Event::Mouse(mouse::Event::ButtonPressed(_))
            | Event::Mouse(mouse::Event::WheelScrolled { .. }) => Some(Message::Activity),
            _ => None,
        });

        Subscription::batch([screen, shell_events])
    }

    fn update(&mut self, message: Self::Message) -> Task<Self::Message> {
        // Effects and policies that leave a screen are the shell's, whoever
        // asked for them.
        match message {
            Message::Copy(value) => return self.copy(value),
            Message::OpenUrl(url) => {
                if let Err(err) = open::that_detached(&url) {
                    eprintln!("could not open {url}: {err}");
                }
                return Task::none();
            }
            Message::Lock => return self.lock(),
            Message::OpenSettings => return self.open_settings(),
            Message::Quit => return self.quit(),
            Message::Settings(message) => return self.update_settings(message),
            Message::Unfocused => {
                if let Shell::Ready {
                    screen: Screen::Vault(vault) | Screen::Settings { vault, .. },
                    ..
                } = &mut self.shell
                {
                    vault.set_temporary_reveal(false);
                }
                return if self.preferences.lock_on_focus_loss {
                    self.lock()
                } else {
                    Task::none()
                };
            }
            Message::TemporaryReveal(held) => {
                if let Shell::Ready {
                    screen: Screen::Vault(vault) | Screen::Settings { vault, .. },
                    ..
                } = &mut self.shell
                {
                    vault.set_temporary_reveal(held);
                    if held {
                        vault.record_activity();
                    }
                }
                return Task::none();
            }
            Message::Activity => {
                if let Shell::Ready {
                    screen: Screen::Vault(vault),
                    ..
                } = &mut self.shell
                {
                    vault.record_activity();
                }
                return Task::none();
            }
            Message::ClipboardExpired(generation) => {
                if generation != self.clipboard.1 {
                    return Task::none();
                }
                return self.clear_clipboard();
            }
            Message::ClipboardRead(current) => {
                return if current.as_deref() == Some(self.clipboard.0.as_str()) {
                    self.wipe_clipboard()
                } else {
                    // The user replaced the system clipboard, so leave their
                    // value alone but stop retaining our old secret locally.
                    self.clipboard.0.clear();
                    Task::none()
                };
            }
            _ => {}
        }

        // The screens borrow `self.shell`, so losing the session is recorded
        // here and applied once that borrow ends.
        let mut lost_session = None;
        let content_width = self.content_width();
        let auto_lock_minutes = self.preferences.auto_lock_minutes;
        let reveal_seconds = self.preferences.auto_hide_reveal_seconds;

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
                            Screen::Master(Box::new(master::State::new(master::Mode::Create, None)))
                        }
                        welcome::Message::ConnectToServer => Screen::Connect {
                            state: Box::default(),
                            return_to: None,
                        },
                    };
                    Task::none()
                }

                Message::Connect(message) => {
                    let Screen::Connect { state, return_to } = &mut *screen else {
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
                            *screen = return_to.take().map_or(Screen::Welcome, |screen| *screen);
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
                                    *screen = Screen::Master(Box::new(master::State::new(
                                        mode,
                                        Some(storage_id),
                                    )));
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
                            let load_vaults = vault::State::load_vaults(session);
                            let mut vault = vault::State::new(page, sync_error);
                            vault.set_content_width(content_width);
                            vault.set_auto_lock_minutes(auto_lock_minutes);
                            vault.set_reveal_seconds(reveal_seconds);
                            *screen = Screen::Vault(Box::new(vault));
                            lift(load_vaults, Message::Vault)
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
                        vault::Outcome::Copy { value, feedback } => Task::batch([
                            cosmic::task::message(Message::Copy(value)),
                            lift(feedback, Message::Vault),
                        ]),
                        vault::Outcome::Locked => cosmic::task::message(Message::Lock),
                    }
                }

                // Handled above, before the session was borrowed.
                Message::Copy(_)
                | Message::OpenUrl(_)
                | Message::Lock
                | Message::OpenSettings
                | Message::Quit
                | Message::Unfocused
                | Message::TemporaryReveal(_)
                | Message::Activity
                | Message::ClipboardExpired(_)
                | Message::ClipboardRead(_)
                | Message::Settings(_) => Task::none(),
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
                Screen::Connect { state, .. } => state.view().map(Message::Connect),
                Screen::Master(state) => state.view().map(Message::Master),
                Screen::Vault(state) => state.view().map(Message::Vault),
                Screen::Settings { state, .. } => state.view().map(Message::Settings),
            },
        }
    }
}

impl App {
    fn is_unlocked(&self) -> bool {
        matches!(
            self.shell,
            Shell::Ready {
                screen: Screen::Vault(_) | Screen::Settings { .. },
                ..
            }
        )
    }

    fn can_open_settings(&self) -> bool {
        matches!(
            self.shell,
            Shell::Ready {
                screen: Screen::Vault(_),
                ..
            }
        )
    }

    fn lock(&mut self) -> Task<Message> {
        let remembered = {
            let Shell::Ready { session, screen } = &mut self.shell else {
                return Task::none();
            };
            if !matches!(screen, Screen::Vault(_) | Screen::Settings { .. }) {
                return Task::none();
            }
            session.lock();
            *screen = Screen::Master(Box::new(master::State::new(master::Mode::Unlock, None)));
            remembered_unlock_task(session)
        };

        let clipboard = if self.preferences.clipboard_clear_on_lock {
            self.clear_clipboard()
        } else {
            Task::none()
        };
        Task::batch([remembered, clipboard])
    }

    fn open_settings(&mut self) -> Task<Message> {
        let preferences = self.preferences.clone();
        let Shell::Ready { session, screen } = &mut self.shell else {
            return Task::none();
        };
        if !matches!(screen, Screen::Vault(_)) {
            return Task::none();
        }

        let load = settings::State::load(session);
        let data_root = session.database_location().client_root().to_path_buf();
        let parked = std::mem::replace(screen, Screen::Welcome);
        if let Screen::Vault(vault) = parked {
            *screen = Screen::Settings {
                state: Box::new(settings::State::new(preferences, data_root)),
                vault,
            };
        }
        lift(load, Message::Settings)
    }

    fn update_settings(&mut self, message: settings::Message) -> Task<Message> {
        let outcome = {
            let Shell::Ready { session, screen } = &mut self.shell else {
                return Task::none();
            };
            let Screen::Settings { state, .. } = screen else {
                return Task::none();
            };
            state.update(message, session)
        };

        match outcome {
            settings::Outcome::None => Task::none(),
            settings::Outcome::Task(task) => lift(task, Message::Settings),
            settings::Outcome::Changed(change) => self.change_preference(change),
            settings::Outcome::Open(target) => cosmic::task::message(Message::OpenUrl(target)),
            settings::Outcome::Sync(storage_id) => {
                let Shell::Ready { session, .. } = &self.shell else {
                    return Task::none();
                };
                let facade = session.facade();
                lift(
                    cosmic::task::future(async move {
                        settings::Message::Synced(
                            zann_cosmic::backend::off_thread(move || {
                                zann_cosmic::backend::local::sync(&facade, Some(storage_id))
                            })
                            .await,
                        )
                    }),
                    Message::Settings,
                )
            }
            settings::Outcome::Close { page } => {
                let Shell::Ready { session, screen } = &mut self.shell else {
                    return Task::none();
                };
                let load_vaults = vault::State::load_vaults(session);
                let parked = std::mem::replace(screen, Screen::Welcome);
                if let Screen::Settings { mut vault, .. } = parked {
                    if let Some(page) = page {
                        vault.replace_page(page);
                    }
                    *screen = Screen::Vault(vault);
                }
                lift(load_vaults, Message::Vault)
            }
            settings::Outcome::AddServer => {
                if let Shell::Ready { screen, .. } = &mut self.shell {
                    if matches!(screen, Screen::Settings { .. }) {
                        let return_to = std::mem::replace(screen, Screen::Welcome);
                        *screen = Screen::Connect {
                            state: Box::default(),
                            return_to: Some(Box::new(return_to)),
                        };
                    }
                }
                Task::none()
            }
            settings::Outcome::Restored { notice } => {
                let Shell::Ready { screen, .. } = &mut self.shell else {
                    return Task::none();
                };
                *screen = Screen::Master(Box::new(
                    master::State::new(master::Mode::Unlock, None).with_notice(notice),
                ));
                Task::none()
            }
        }
    }

    fn change_preference(&mut self, change: preferences::Change) -> Task<Message> {
        let mut next = self.preferences.clone();
        preferences::apply(&mut next, change);
        let Some(store) = self.preference_store.as_ref() else {
            return Task::none();
        };
        if let Err(err) = store.save_change(&next, change) {
            eprintln!("could not save settings: {err}");
            return Task::none();
        }

        self.preferences = next;
        if matches!(change, preferences::Change::ClipboardSeconds(_)) {
            // Cancel a timer scheduled under the previous policy.
            self.clipboard.1 += 1;
        }
        let language_changed = matches!(change, preferences::Change::Language(_));
        if language_changed {
            zann_cosmic::i18n::set_language(self.preferences.language.as_deref());
        }
        if let Shell::Ready { screen, .. } = &mut self.shell {
            match screen {
                Screen::Vault(vault) => {
                    if language_changed {
                        vault.refresh_translations();
                    }
                    vault.set_auto_lock_minutes(self.preferences.auto_lock_minutes);
                    vault.set_reveal_seconds(self.preferences.auto_hide_reveal_seconds);
                }
                Screen::Settings { state, vault } => {
                    state.preferences_changed(self.preferences.clone());
                    if language_changed {
                        vault.refresh_translations();
                    }
                    vault.set_auto_lock_minutes(self.preferences.auto_lock_minutes);
                    vault.set_reveal_seconds(self.preferences.auto_hide_reveal_seconds);
                }
                _ => {}
            }
        }
        Task::none()
    }

    fn quit(&mut self) -> Task<Message> {
        if self.preferences.clipboard_clear_on_exit {
            return self.clear_clipboard().chain(cosmic::iced::exit());
        }
        cosmic::iced::exit()
    }

    fn copy(&mut self, value: String) -> Task<Message> {
        self.clipboard.0 = value.clone();
        self.clipboard.1 += 1;
        let generation = self.clipboard.1;
        let write = cosmic::iced::clipboard::write(value);
        let seconds = u64::from(self.preferences.clipboard_clear_seconds);
        if seconds == 0 {
            return write;
        }
        Task::batch([
            write,
            cosmic::task::future(async move {
                tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
                Message::ClipboardExpired(generation)
            }),
        ])
    }

    fn clear_clipboard(&mut self) -> Task<Message> {
        if self.clipboard.0.is_empty() {
            return Task::none();
        }
        if self.preferences.clipboard_clear_if_unchanged {
            return cosmic::iced::clipboard::read()
                .map(|value| cosmic::Action::App(Message::ClipboardRead(value)));
        }
        self.wipe_clipboard()
    }

    fn wipe_clipboard(&mut self) -> Task<Message> {
        self.clipboard.0.clear();
        cosmic::iced::clipboard::write(String::new())
    }

    fn content_width(&self) -> f32 {
        if self.core.nav_bar_active() {
            self.window_width - NAV_WIDTH
        } else {
            self.window_width
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
