//! Native settings screen backed by shared semantics and platform capabilities.
//!
//! The sections and choices match the product contract, while libcosmic owns
//! the actual controls. Unsupported workflows are omitted instead of exposing
//! inert desktop controls.

use std::path::PathBuf;

use cosmic::dialog::file_chooser::{self, FileFilter};
use cosmic::iced::{Alignment, Length, Task};
use cosmic::{theme, widget, Element};
use zann_client::app::local::{
    ApplePasswordsImportReport, ApplePasswordsPreflight, BackupExportReport, RememberedUnlock,
    Snapshot, SnapshotRestore, StorageSummary, VerifyReport,
};
use zann_ui_core::settings::{AUTO_LOCK_MINUTES, CLIPBOARD_SECONDS, REVEAL_SECONDS};
use zann_ui_core::{DevicePreferences, SettingsSection, LANGUAGES};

use crate::backend::local;
use crate::backend::off_thread;
use crate::i18n::{t, t_args};
use crate::preferences::Change;
use crate::session::Session;

const DOCS_URL: &str = "https://docs.zann.app";
const SOURCE_URL: &str = "https://github.com/constxife/zann";

pub struct State {
    section: SettingsSection,
    preferences: DevicePreferences,
    close_to_tray: bool,
    remembered: Option<RememberedUnlock>,
    storages: Vec<StorageSummary>,
    data_root: PathBuf,
    enrolling: bool,
    unlock_busy: bool,
    syncing: bool,
    busy: bool,
    error: Option<String>,
    /// Result of the last export, kept on screen so the path can be read off
    /// and the file found.
    exported: Option<BackupExportReport>,
    apple_selection: Option<AppleSelection>,
    apple_imported: Option<ApplePasswordsImportReport>,
    import_target_storage_id: String,
    refresh_vault_on_close: bool,
    snapshots: Vec<Snapshot>,
    restore_target: String,
    /// The snapshot a restore has been asked for but not yet confirmed.
    /// Restoring throws away everything since it was taken, so it is never one
    /// click away from a list of dates.
    confirming: Option<Snapshot>,
    verified: Option<Box<VerifyReport>>,
}

#[derive(Clone, Debug)]
pub struct AppleSelection {
    path: String,
    preflight: ApplePasswordsPreflight,
}

#[derive(Clone, Debug)]
pub struct Loaded {
    remembered: RememberedUnlock,
    storages: Vec<StorageSummary>,
    current_storage_id: String,
}

#[derive(Clone, Debug)]
pub enum Message {
    Select(SettingsSection),
    Set(Change),
    Loaded(Result<Loaded, String>),
    RememberedLoaded(Result<RememberedUnlock, String>),
    Enroll,
    Remove(String),
    UseKeystore,
    Forget,
    Export,
    Exported(Result<BackupExportReport, String>),
    ChooseApplePasswords,
    ApplePrepared(Result<Option<AppleSelection>, String>),
    ImportApplePasswords,
    AppleImported(Result<ApplePasswordsImportReport, String>),
    Snapshot,
    Snapshots(Result<Vec<Snapshot>, String>),
    /// Ask for a restore. Shows the confirmation; does not touch anything.
    AskRestore(Box<Snapshot>),
    CancelRestore,
    ConfirmRestore(String),
    Restored(Result<Box<SnapshotRestore>, String>),
    Verify,
    Verified(Result<VerifyReport, String>),
    SyncNow(String),
    Synced(Result<(), String>),
    AddServer,
    Open(String),
    Close,
    CloseLoaded(Result<local::ItemsPage, String>),
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Changed(Change),
    Sync(String),
    AddServer,
    Open(String),
    Close {
        page: Option<local::ItemsPage>,
    },
    /// A restore replaced the database, so the vault is locked and the screens
    /// behind this one are showing rows that no longer exist.
    Restored {
        notice: String,
    },
}

impl State {
    pub fn new(preferences: DevicePreferences, close_to_tray: bool, data_root: PathBuf) -> Self {
        Self {
            section: SettingsSection::General,
            preferences,
            close_to_tray,
            remembered: None,
            storages: Vec::new(),
            data_root,
            enrolling: false,
            unlock_busy: false,
            syncing: false,
            busy: false,
            error: None,
            exported: None,
            apple_selection: None,
            apple_imported: None,
            import_target_storage_id: "local".to_string(),
            refresh_vault_on_close: false,
            snapshots: Vec::new(),
            restore_target: String::new(),
            confirming: None,
            verified: None,
        }
    }

    pub fn load(session: &Session) -> Task<Message> {
        let facade = session.facade();
        let snapshots = session.facade();
        Task::batch([
            cosmic::task::future(async move {
                Message::Loaded(
                    off_thread(move || {
                        Ok(Loaded {
                            remembered: local::remembered_unlock(&facade)?,
                            storages: local::storages(&facade)?,
                            current_storage_id: local::current_storage_id(&facade),
                        })
                    })
                    .await,
                )
            }),
            cosmic::task::future(async move {
                Message::Snapshots(off_thread(move || local::snapshots(&snapshots)).await)
            }),
        ])
    }

    pub fn preferences_changed(&mut self, preferences: DevicePreferences) {
        self.preferences = preferences;
    }

    pub fn close_to_tray_changed(&mut self, close_to_tray: bool) {
        self.close_to_tray = close_to_tray;
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::Select(section) => self.section = section,
            Message::Set(change) => return Outcome::Changed(change),
            Message::Loaded(Ok(loaded)) => {
                self.remembered = Some(loaded.remembered);
                self.storages = loaded.storages;
                self.import_target_storage_id = loaded.current_storage_id;
            }
            Message::Loaded(Err(err)) => self.error = Some(err),
            Message::RememberedLoaded(result) => {
                self.unlock_busy = false;
                self.enrolling = false;
                match result {
                    Ok(remembered) => self.remembered = Some(remembered),
                    Err(err) => self.error = Some(err),
                }
            }
            Message::Enroll => {
                if self.unlock_busy {
                    return Outcome::None;
                }
                self.unlock_busy = true;
                self.enrolling = true;
                self.error = None;
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::RememberedLoaded(
                        off_thread(move || {
                            local::enroll_hardware_key(&facade, String::new())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }
            Message::Remove(credential_id) => {
                if self.unlock_busy {
                    return Outcome::None;
                }
                self.unlock_busy = true;
                self.error = None;
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::RememberedLoaded(
                        off_thread(move || {
                            local::remove_hardware_key(&facade, credential_id)?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }
            Message::UseKeystore => {
                if self.unlock_busy {
                    return Outcome::None;
                }
                self.unlock_busy = true;
                self.error = None;
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::RememberedLoaded(
                        off_thread(move || {
                            facade
                                .remember_with_keystore()
                                .map_err(|err| err.to_string())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }
            Message::Forget => {
                if self.unlock_busy {
                    return Outcome::None;
                }
                self.unlock_busy = true;
                self.error = None;
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    Message::RememberedLoaded(
                        off_thread(move || {
                            facade.forget_remembered().map_err(|err| err.to_string())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }
            Message::Export => {
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                self.exported = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Exported(off_thread(move || local::export_backup(&facade)).await)
                }));
            }

            Message::Exported(Ok(report)) => {
                self.busy = false;
                self.exported = Some(report);
            }

            Message::Exported(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }

            Message::ChooseApplePasswords => {
                if self.busy {
                    return Outcome::None;
                }
                self.busy = true;
                self.error = None;
                let facade = session.facade();
                return Outcome::Task(cosmic::task::future(async move {
                    let result = match file_chooser::open::Dialog::new()
                        .title(t("settings.backups.importAppleAction"))
                        .filter(FileFilter::new("Apple Passwords CSV").glob("*.csv"))
                        .open_file()
                        .await
                    {
                        Ok(response) => match response.url().to_file_path() {
                            Ok(path) => {
                                let path = path.display().to_string();
                                let worker_path = path.clone();
                                off_thread(move || {
                                    local::apple_passwords_preflight(&facade, worker_path)
                                })
                                .await
                                .map(|preflight| Some(AppleSelection { path, preflight }))
                            }
                            Err(()) => Err(t("settings.backups.importApplePickerLocalOnly")),
                        },
                        Err(file_chooser::Error::Cancelled) => Ok(None),
                        Err(err) => Err(t_args(
                            "settings.backups.importApplePickerFailed",
                            &[("error", &err.to_string())],
                        )),
                    };
                    Message::ApplePrepared(result)
                }));
            }

            Message::ApplePrepared(Ok(Some(selection))) => {
                self.busy = false;
                self.apple_selection = Some(selection);
                self.apple_imported = None;
            }

            Message::ApplePrepared(Ok(None)) => self.busy = false,

            Message::ApplePrepared(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }

            Message::ImportApplePasswords => {
                if self.busy {
                    return Outcome::None;
                }
                let Some(selection) = self.apple_selection.clone() else {
                    return Outcome::None;
                };
                if self.import_target_storage_id.is_empty() {
                    self.error = Some(t("settings.backups.importAppleTargetMissing"));
                    return Outcome::None;
                }
                let facade = session.facade();
                let target_storage_id = self.import_target_storage_id.clone();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::AppleImported(
                        off_thread(move || {
                            local::import_apple_passwords(
                                &facade,
                                selection.path,
                                target_storage_id,
                            )
                        })
                        .await,
                    )
                }));
            }

            Message::AppleImported(Ok(report)) => {
                self.busy = false;
                self.apple_selection = None;
                self.apple_imported = Some(report);
                self.refresh_vault_on_close = true;
                let target_is_remote = self.storages.iter().any(|storage| {
                    storage.id == self.import_target_storage_id && storage.kind == "remote"
                });
                if target_is_remote && !self.syncing {
                    self.syncing = true;
                    return Outcome::Sync(self.import_target_storage_id.clone());
                }
            }

            Message::AppleImported(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }

            Message::Snapshot => {
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Snapshots(
                        off_thread(move || {
                            local::snapshot_now(&facade)?;
                            local::snapshots(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::Snapshots(Ok(snapshots)) => {
                self.busy = false;
                self.restore_target = session.facade().snapshot_restore_target();
                self.snapshots = snapshots;
            }

            Message::Snapshots(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }

            Message::AskRestore(snapshot) => {
                if self.busy {
                    return Outcome::None;
                }
                self.error = None;
                self.confirming = Some(*snapshot);
            }

            Message::CancelRestore => self.confirming = None,

            Message::ConfirmRestore(path) => {
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                self.confirming = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Restored(
                        off_thread(move || local::restore_snapshot(&facade, path))
                            .await
                            .map(Box::new),
                    )
                }));
            }

            Message::Restored(Ok(outcome)) => {
                self.busy = false;
                // The vault is locked and everything on screen behind this is
                // stale, so the shell takes over rather than this screen trying
                // to refresh itself.
                let notice = if outcome.identity_replaced {
                    "Restored. Unlock with the master password that was in use when \
                     that snapshot was taken."
                        .to_string()
                } else {
                    "Restored. Unlock to continue.".to_string()
                };
                return Outcome::Restored { notice };
            }

            Message::Restored(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }

            Message::Verify => {
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                self.verified = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Verified(off_thread(move || local::verify(&facade)).await)
                }));
            }

            Message::Verified(Ok(report)) => {
                self.busy = false;
                self.verified = Some(Box::new(report));
            }

            Message::Verified(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }
            Message::SyncNow(storage_id) => {
                if self.syncing {
                    return Outcome::None;
                }
                self.syncing = true;
                self.error = None;
                return Outcome::Sync(storage_id);
            }
            Message::Synced(result) => {
                self.syncing = false;
                self.error = result.err();
            }
            Message::AddServer => return Outcome::AddServer,
            Message::Open(target) => return Outcome::Open(target),
            Message::Close => {
                if !self.refresh_vault_on_close {
                    return Outcome::Close { page: None };
                }
                if self.busy || self.syncing {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::CloseLoaded(
                        off_thread(move || local::items(&facade, None, None)).await,
                    )
                }));
            }
            Message::CloseLoaded(Ok(page)) => {
                self.busy = false;
                return Outcome::Close { page: Some(page) };
            }
            Message::CloseLoaded(Err(err)) => {
                self.busy = false;
                self.error = Some(err);
            }
        }
        Outcome::None
    }
}

mod view;
