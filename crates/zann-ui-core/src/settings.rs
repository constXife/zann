//! Semantic settings shared by native and web clients.
//!
//! This is deliberately not a widget schema. It defines stable meaning,
//! defaults and capabilities; Vue, libcosmic and SwiftUI still render native
//! controls and adaptive navigation.

use serde::{Deserialize, Serialize};

pub const AUTO_LOCK_MINUTES: &[u32] = &[0, 1, 5, 10, 30, 60];
pub const CLIPBOARD_SECONDS: &[u32] = &[0, 15, 30, 60, 120, 300];
pub const REVEAL_SECONDS: &[u32] = &[0, 10, 20, 30, 60];
pub const TRASH_RETENTION_DAYS: &[u32] = &[0, 30, 90];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsSection {
    General,
    Security,
    Accounts,
    Backups,
    About,
}

impl SettingsSection {
    pub const ALL: &'static [Self] = &[
        Self::General,
        Self::Security,
        Self::Accounts,
        Self::Backups,
        Self::About,
    ];

    #[must_use]
    pub const fn label_key(self) -> &'static str {
        match self {
            Self::General => "settings.tabs.general",
            Self::Security => "settings.tabs.security",
            Self::Accounts => "settings.tabs.accounts",
            Self::Backups => "settings.tabs.backups",
            Self::About => "settings.tabs.about",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingScope {
    Device,
    Shell,
    Account,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    BackgroundWindow,
    HardwareKey,
    Keystore,
    TrashPurge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingId {
    Language,
    AutoLockMinutes,
    LockOnFocusLoss,
    LockOnHidden,
    ClipboardClearSeconds,
    ClipboardClearOnLock,
    ClipboardClearOnExit,
    ClipboardClearIfUnchanged,
    AutoHideRevealSeconds,
    TrashRetentionDays,
    RememberedUnlock,
}

pub struct SettingDescriptor {
    pub id: SettingId,
    pub section: SettingsSection,
    pub scope: SettingScope,
    pub capability: Option<Capability>,
}

pub const SETTINGS_CATALOG: &[SettingDescriptor] = &[
    descriptor(
        SettingId::Language,
        SettingsSection::General,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::AutoLockMinutes,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::LockOnFocusLoss,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::LockOnHidden,
        SettingsSection::Security,
        SettingScope::Device,
        Some(Capability::BackgroundWindow),
    ),
    descriptor(
        SettingId::ClipboardClearSeconds,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::ClipboardClearOnLock,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::ClipboardClearOnExit,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::ClipboardClearIfUnchanged,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::AutoHideRevealSeconds,
        SettingsSection::Security,
        SettingScope::Device,
        None,
    ),
    descriptor(
        SettingId::TrashRetentionDays,
        SettingsSection::General,
        SettingScope::Account,
        Some(Capability::TrashPurge),
    ),
    descriptor(
        SettingId::RememberedUnlock,
        SettingsSection::Security,
        SettingScope::Device,
        Some(Capability::Keystore),
    ),
];

const fn descriptor(
    id: SettingId,
    section: SettingsSection,
    scope: SettingScope,
    capability: Option<Capability>,
) -> SettingDescriptor {
    SettingDescriptor {
        id,
        section,
        scope,
        capability,
    }
}

/// Portable device policies. Shell geometry, tray behavior and transient
/// navigation state intentionally live in each platform adapter instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DevicePreferences {
    pub language: Option<String>,
    pub auto_lock_minutes: u32,
    pub lock_on_focus_loss: bool,
    pub lock_on_hidden: bool,
    pub clipboard_clear_seconds: u32,
    pub clipboard_clear_on_lock: bool,
    pub clipboard_clear_on_exit: bool,
    pub clipboard_clear_if_unchanged: bool,
    pub auto_hide_reveal_seconds: u32,
    pub trash_auto_purge_days: u32,
}

impl Default for DevicePreferences {
    fn default() -> Self {
        Self {
            language: None,
            auto_lock_minutes: 10,
            lock_on_focus_loss: false,
            lock_on_hidden: false,
            clipboard_clear_seconds: 60,
            clipboard_clear_on_lock: true,
            clipboard_clear_on_exit: true,
            clipboard_clear_if_unchanged: true,
            auto_hide_reveal_seconds: 20,
            trash_auto_purge_days: 90,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_defaults_are_the_shared_device_defaults() {
        let settings = DevicePreferences::default();
        assert_eq!(settings.auto_lock_minutes, 10);
        assert_eq!(settings.clipboard_clear_seconds, 60);
        assert_eq!(settings.auto_hide_reveal_seconds, 20);
        assert_eq!(settings.trash_auto_purge_days, 90);
    }

    #[test]
    fn every_section_has_a_stable_catalogue_entry() {
        assert_eq!(SettingsSection::ALL.len(), 5);
        for section in SettingsSection::ALL {
            assert!(section.label_key().starts_with("settings.tabs."));
        }
    }
}
