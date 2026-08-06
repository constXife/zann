// SPDX-License-Identifier: MIT

//! The settings the app keeps between runs.
//!
//! The names and the defaults are the desktop app's `DesktopSettings`, so that
//! "auto-lock after 10 minutes" means the same thing in both clients and a
//! reader moving between them is not asked to learn a second vocabulary.
//!
//! The file is not shared, though. `desktop.json` carries a wrapped master key
//! and a biometry backup that this app has no way to produce, and a round trip
//! through a struct without those fields would quietly drop them — so this one
//! keeps its own, next to the database like the rest of the client state.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::backend::{client_root, default_db_url};

const FILENAME: &str = "cosmic.json";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `None` is whatever the environment asks for, which is what an unset
    /// preference means in the desktop app too.
    pub language: Option<String>,
    pub close_to_tray: bool,
    /// Minutes of no input before the vault locks itself. `0` is never.
    pub auto_lock_minutes: u32,
    pub lock_on_hidden: bool,
    pub lock_on_focus_loss: bool,
    /// Seconds a copied secret stays on the clipboard. `0` is never.
    pub clipboard_clear_seconds: u32,
    pub clipboard_clear_on_lock: bool,
    pub clipboard_clear_on_exit: bool,
    /// Only clear if nothing else has written to the clipboard since — taking
    /// away what someone copied afterwards would be worse than leaving ours.
    pub clipboard_clear_if_unchanged: bool,
    /// Seconds a revealed field stays revealed. `0` is never.
    pub auto_hide_reveal_seconds: u32,

    /// Where the reader left the app, so it opens where they left it. The
    /// desktop app keeps the same three, and two more this one does not: the
    /// search query and the selected item. Both say what someone went looking
    /// for, and neither is worth writing to disk to save a click.
    pub list_width: f32,
    pub last_category: Option<String>,
    /// `None` is every folder; `Some("")` is the items that are in none.
    pub last_folder: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: None,
            close_to_tray: true,
            auto_lock_minutes: 10,
            lock_on_hidden: false,
            lock_on_focus_loss: false,
            clipboard_clear_seconds: 60,
            clipboard_clear_on_lock: true,
            clipboard_clear_on_exit: true,
            clipboard_clear_if_unchanged: true,
            auto_hide_reveal_seconds: 20,
            list_width: 400.0,
            last_category: None,
            last_folder: None,
        }
    }
}

/// One field, so the screen reports what the user changed rather than handing
/// back a whole [`Settings`] the shell would have to diff.
#[derive(Clone, Copy, Debug)]
pub enum Change {
    Language(Option<&'static str>),
    CloseToTray(bool),
    AutoLockMinutes(u32),
    LockOnHidden(bool),
    LockOnFocusLoss(bool),
    ClipboardSeconds(u32),
    ClipboardOnLock(bool),
    ClipboardOnExit(bool),
    ClipboardIfUnchanged(bool),
    AutoHideRevealSeconds(u32),
}

/// Where the reader was, reported by the vault when it moves. Separate from
/// [`Change`] because nothing here is a preference the settings screen shows.
#[derive(Clone, Debug)]
pub enum Place {
    ListWidth(f32),
    Category(Option<String>),
    Folder(Option<String>),
}

impl Settings {
    /// Anything unreadable falls back to the defaults rather than blocking the
    /// app: settings are a preference, not the vault.
    pub fn load() -> Self {
        std::fs::read_to_string(path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|err| err.to_string())?;
        std::fs::write(path, text).map_err(|err| err.to_string())
    }

    pub fn set(&mut self, change: Change) {
        match change {
            Change::Language(value) => self.language = value.map(str::to_string),
            Change::CloseToTray(value) => self.close_to_tray = value,
            Change::AutoLockMinutes(value) => self.auto_lock_minutes = value,
            Change::LockOnHidden(value) => self.lock_on_hidden = value,
            Change::LockOnFocusLoss(value) => self.lock_on_focus_loss = value,
            Change::ClipboardSeconds(value) => self.clipboard_clear_seconds = value,
            Change::ClipboardOnLock(value) => self.clipboard_clear_on_lock = value,
            Change::ClipboardOnExit(value) => self.clipboard_clear_on_exit = value,
            Change::ClipboardIfUnchanged(value) => self.clipboard_clear_if_unchanged = value,
            Change::AutoHideRevealSeconds(value) => self.auto_hide_reveal_seconds = value,
        }
    }

    /// Returns whether anything moved, so an unchanged place does not rewrite
    /// the file — dragging a splitter reports on every pixel.
    pub fn remember(&mut self, place: Place) -> bool {
        match place {
            Place::ListWidth(value) => {
                let changed = (self.list_width - value).abs() >= 1.0;
                self.list_width = value;
                changed
            }
            Place::Category(value) => {
                let changed = self.last_category != value;
                self.last_category = value;
                changed
            }
            Place::Folder(value) => {
                let changed = self.last_folder != value;
                self.last_folder = value;
                changed
            }
        }
    }
}

pub fn path() -> PathBuf {
    client_root(&default_db_url()).join(FILENAME)
}
