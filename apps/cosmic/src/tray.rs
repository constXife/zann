// SPDX-License-Identifier: MIT

//! The tray icon.
//!
//! COSMIC has no tray of its own: the panel's status area is a
//! StatusNotifierItem host, so the icon is an SNI on the session bus and `ksni`
//! is what speaks it. That also means the icon is not guaranteed to exist —
//! [`start`] says so, and the shell reads that as "the close button still
//! closes the app", because a window with nowhere to go and no way back would
//! leave the user with a process they cannot reach.
//!
//! The tray runs on its own thread and can only hand work over, never do it:
//! everything it is asked for ends up as a [`Command`] the shell acts on.

use std::sync::{Mutex, OnceLock};

use cosmic::iced::futures::channel::mpsc::{self, UnboundedReceiver, UnboundedSender};
use cosmic::iced::futures::{Stream, StreamExt};
use cosmic::iced::Subscription;
use ksni::blocking::TrayMethods;
use ksni::menu::StandardItem;
use ksni::MenuItem;

use crate::i18n::t;

/// What the tray can ask the shell to do. Nothing here is done by the tray
/// itself — a menu callback that blocks would freeze the menu.
#[derive(Clone, Copy, Debug)]
pub enum Command {
    /// Put the window back, or focus the one that is already there.
    Show,
    /// The window, with the settings on top of it.
    Settings,
    Lock,
    Quit,
}

/// The receiving half of the channel, parked in a static because a
/// [`Subscription`] is built from a bare `fn` with nothing captured. There is
/// one tray per process, so there is nothing here that wants to be per-app.
static COMMANDS: OnceLock<Mutex<Option<UnboundedReceiver<Command>>>> = OnceLock::new();

struct Tray {
    /// Doubles as the icon name: the desktop entry and the hicolor icons are
    /// installed under the same id.
    app_id: &'static str,
    title: &'static str,
    commands: UnboundedSender<Command>,
}

impl Tray {
    /// The shell outlives the tray, so a closed channel only ever means the app
    /// is already on its way out and there is no one left to tell.
    fn send(&self, command: Command) {
        let _ = self.commands.unbounded_send(command);
    }

    fn item(&self, key: &str, command: Command) -> MenuItem<Self> {
        StandardItem {
            label: t(key),
            activate: Box::new(move |tray: &mut Self| tray.send(command)),
            ..Default::default()
        }
        .into()
    }
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        self.app_id.to_string()
    }

    fn title(&self) -> String {
        self.title.to_string()
    }

    fn icon_name(&self) -> String {
        self.app_id.to_string()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(Command::Show);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            self.item("common.show", Command::Show),
            self.item("common.settings", Command::Settings),
            MenuItem::Separator,
            self.item("common.lock", Command::Lock),
            self.item("common.quit", Command::Quit),
        ]
    }
}

/// Dropping the handle takes the icon down with it, so it is parked for the
/// life of the process rather than handed back for a caller to keep alive.
static HANDLE: OnceLock<ksni::blocking::Handle<Tray>> = OnceLock::new();

/// Puts the icon up, and says whether it went. `false` when the desktop has
/// nowhere to put it — no StatusNotifierWatcher on the bus, or one with no host
/// behind it.
pub fn start(app_id: &'static str, title: &'static str) -> bool {
    let (sender, receiver) = mpsc::unbounded();

    let Ok(handle) = Tray {
        app_id,
        title,
        commands: sender,
    }
    .spawn()
    .inspect_err(|err| eprintln!("no tray: {err}")) else {
        return false;
    };

    // Both only fail if `start` ran twice, which would leave the second tray
    // talking to a channel nobody reads.
    COMMANDS.set(Mutex::new(Some(receiver))).is_ok() && HANDLE.set(handle).is_ok()
}

/// Redraws the menu. Its labels come from the catalogue, and the host caches
/// what it was last given, so a language change has to be pushed rather than
/// waited for.
pub fn refresh() {
    if let Some(handle) = HANDLE.get() {
        handle.update(|_| {});
    }
}

/// The commands the tray has raised. Empty, and cheap, when there is no tray.
pub fn subscription() -> Subscription<Command> {
    Subscription::run(commands)
}

fn commands() -> impl Stream<Item = Command> {
    // Taken rather than borrowed: iced builds a recipe once and keeps it, so a
    // second call would only ever be a restart with nothing left to replay.
    let receiver = COMMANDS
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|mut slot| slot.take()));
    cosmic::iced::futures::stream::iter(receiver).flatten()
}
