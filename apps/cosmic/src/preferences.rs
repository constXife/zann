//! Adapter for the portable settings kept in `desktop.json`.
//!
//! The model and defaults are shared, but this file adapter is intentionally
//! thin: a later config repository can replace it without changing any screen.
//! Writes patch one owned field into the existing JSON object, preserving
//! Tauri-only and future fields.

use std::path::{Path, PathBuf};

use serde_json::Value;
use zann_ui_core::DevicePreferences;

const FILENAME: &str = "desktop.json";

#[derive(Clone, Copy, Debug)]
pub enum Change {
    Language(Option<&'static str>),
    AutoLockMinutes(u32),
    LockOnFocusLoss(bool),
    ClipboardSeconds(u32),
    ClipboardOnLock(bool),
    ClipboardOnExit(bool),
    ClipboardIfUnchanged(bool),
    AutoHideRevealSeconds(u32),
}

impl Change {
    fn key(self) -> &'static str {
        match self {
            Self::Language(_) => "language",
            Self::AutoLockMinutes(_) => "auto_lock_minutes",
            Self::LockOnFocusLoss(_) => "lock_on_focus_loss",
            Self::ClipboardSeconds(_) => "clipboard_clear_seconds",
            Self::ClipboardOnLock(_) => "clipboard_clear_on_lock",
            Self::ClipboardOnExit(_) => "clipboard_clear_on_exit",
            Self::ClipboardIfUnchanged(_) => "clipboard_clear_if_unchanged",
            Self::AutoHideRevealSeconds(_) => "auto_hide_reveal_seconds",
        }
    }

    fn value(self) -> Value {
        match self {
            Self::Language(value) => value.map_or(Value::Null, |value| Value::String(value.into())),
            Self::AutoLockMinutes(value)
            | Self::ClipboardSeconds(value)
            | Self::AutoHideRevealSeconds(value) => Value::from(value),
            Self::LockOnFocusLoss(value)
            | Self::ClipboardOnLock(value)
            | Self::ClipboardOnExit(value)
            | Self::ClipboardIfUnchanged(value) => Value::Bool(value),
        }
    }
}

#[derive(Clone)]
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(client_root: &Path) -> Self {
        Self {
            path: client_root.join(FILENAME),
        }
    }

    pub fn load(&self) -> DevicePreferences {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Patch only the field the user changed. Reloading immediately before the
    /// patch prevents this client from writing a stale copy of unrelated keys.
    pub fn save_change(
        &self,
        preferences: &DevicePreferences,
        change: Change,
    ) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
        let mut root = std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        root.insert(change.key().to_string(), change.value());

        // Validate that the value now represented on disk agrees with the
        // in-memory model before replacing the file.
        let serialized = serde_json::to_string_pretty(&root).map_err(|err| err.to_string())?;
        let parsed: DevicePreferences =
            serde_json::from_str(&serialized).map_err(|err| err.to_string())?;
        if &parsed != preferences {
            return Err("settings patch did not preserve the current device preferences".into());
        }

        let temporary = self.path.with_extension("json.cosmic.tmp");
        std::fs::write(&temporary, serialized).map_err(|err| err.to_string())?;
        std::fs::rename(&temporary, &self.path).map_err(|err| err.to_string())
    }
}

pub fn apply(preferences: &mut DevicePreferences, change: Change) {
    match change {
        Change::Language(value) => preferences.language = value.map(str::to_string),
        Change::AutoLockMinutes(value) => preferences.auto_lock_minutes = value,
        Change::LockOnFocusLoss(value) => preferences.lock_on_focus_loss = value,
        Change::ClipboardSeconds(value) => preferences.clipboard_clear_seconds = value,
        Change::ClipboardOnLock(value) => preferences.clipboard_clear_on_lock = value,
        Change::ClipboardOnExit(value) => preferences.clipboard_clear_on_exit = value,
        Change::ClipboardIfUnchanged(value) => {
            preferences.clipboard_clear_if_unchanged = value;
        }
        Change::AutoHideRevealSeconds(value) => preferences.auto_hide_reveal_seconds = value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_preserves_fields_owned_by_other_clients() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::new(dir.path());
        std::fs::write(
            dir.path().join(FILENAME),
            r#"{"auto_lock_minutes":5,"close_to_tray":false,"future":{"value":1}}"#,
        )
        .expect("fixture");
        let mut preferences = store.load();
        assert_eq!(preferences.auto_lock_minutes, 5);

        let change = Change::AutoLockMinutes(30);
        apply(&mut preferences, change);
        store.save_change(&preferences, change).expect("save");

        let value: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(FILENAME)).expect("read"),
        )
        .expect("json");
        assert_eq!(value["auto_lock_minutes"], 30);
        assert_eq!(value["close_to_tray"], false);
        assert_eq!(value["future"]["value"], 1);
    }
}
