//! Native settings screen backed by shared semantics and platform capabilities.
//!
//! The sections and choices match the product contract, while libcosmic owns
//! the actual controls. Unsupported workflows are omitted instead of exposing
//! inert desktop controls.

use std::path::PathBuf;

use cosmic::iced::{Alignment, Length, Task};
use cosmic::{theme, widget, Element};
use zann_ffi::{
    BackupExportReport, RememberedUnlockFfi, SnapshotFfi, SnapshotRestoreFfi, StorageSummaryFfi,
    VerifyReportFfi,
};
use zann_ui_core::settings::{AUTO_LOCK_MINUTES, CLIPBOARD_SECONDS, REVEAL_SECONDS};
use zann_ui_core::{DevicePreferences, SettingsSection, LANGUAGES};

use crate::backend::local;
use crate::backend::off_thread;
use crate::i18n::t;
use crate::preferences::Change;
use crate::session::Session;

const DOCS_URL: &str = "https://docs.zann.app";
const SOURCE_URL: &str = "https://github.com/constxife/zann";

pub struct State {
    section: SettingsSection,
    preferences: DevicePreferences,
    remembered: Option<RememberedUnlockFfi>,
    storages: Vec<StorageSummaryFfi>,
    data_root: PathBuf,
    enrolling: bool,
    unlock_busy: bool,
    syncing: bool,
    busy: bool,
    error: Option<String>,
    /// Result of the last export, kept on screen so the path can be read off
    /// and the file found.
    exported: Option<BackupExportReport>,
    snapshots: Vec<SnapshotFfi>,
    restore_target: String,
    /// The snapshot a restore has been asked for but not yet confirmed.
    /// Restoring throws away everything since it was taken, so it is never one
    /// click away from a list of dates.
    confirming: Option<SnapshotFfi>,
    verified: Option<Box<VerifyReportFfi>>,
}

#[derive(Clone, Debug)]
pub struct Loaded {
    remembered: RememberedUnlockFfi,
    storages: Vec<StorageSummaryFfi>,
}

#[derive(Clone, Debug)]
pub enum Message {
    Select(SettingsSection),
    Set(Change),
    Loaded(Result<Loaded, String>),
    RememberedLoaded(Result<RememberedUnlockFfi, String>),
    Enroll,
    Remove(String),
    UseKeystore,
    Forget,
    Export,
    Exported(Result<BackupExportReport, String>),
    Snapshot,
    Snapshots(Result<Vec<SnapshotFfi>, String>),
    /// Ask for a restore. Shows the confirmation; does not touch anything.
    AskRestore(Box<SnapshotFfi>),
    CancelRestore,
    ConfirmRestore(String),
    Restored(Result<Box<SnapshotRestoreFfi>, String>),
    Verify,
    Verified(Result<VerifyReportFfi, String>),
    SyncNow(String),
    Synced(Result<(), String>),
    AddServer,
    Open(String),
    Close,
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Changed(Change),
    Sync(String),
    AddServer,
    Open(String),
    Close,
    /// A restore replaced the database, so the vault is locked and the screens
    /// behind this one are showing rows that no longer exist.
    Restored {
        notice: String,
    },
}

impl State {
    pub fn new(preferences: DevicePreferences, data_root: PathBuf) -> Self {
        Self {
            section: SettingsSection::General,
            preferences,
            remembered: None,
            storages: Vec::new(),
            data_root,
            enrolling: false,
            unlock_busy: false,
            syncing: false,
            busy: false,
            error: None,
            exported: None,
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

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::Select(section) => self.section = section,
            Message::Set(change) => return Outcome::Changed(change),
            Message::Loaded(Ok(loaded)) => {
                self.remembered = Some(loaded.remembered);
                self.storages = loaded.storages;
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
            Message::Close => return Outcome::Close,
        }
        Outcome::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut sections =
            widget::column::with_capacity(SettingsSection::ALL.len()).spacing(spacing.space_xxs);
        for section in SettingsSection::ALL {
            sections = sections.push(
                widget::button::custom(
                    widget::row::with_capacity(2)
                        .push(
                            widget::icon::from_name(section_icon(*section))
                                .size(16)
                                .icon(),
                        )
                        .push(widget::text::body(t(section.label_key())))
                        .spacing(spacing.space_xs)
                        .align_y(Alignment::Center),
                )
                .class(if *section == self.section {
                    theme::Button::Suggested
                } else {
                    theme::Button::Text
                })
                .width(Length::Fill)
                .on_press(Message::Select(*section)),
            );
        }

        let body = match self.section {
            SettingsSection::General => self.general(),
            SettingsSection::Security => self.security(),
            SettingsSection::Accounts => self.accounts(),
            SettingsSection::Backups => self.backups(),
            SettingsSection::About => self.about(),
        };
        let header = widget::row::with_capacity(2)
            .push(widget::text::title3(t("settings.title")).width(Length::Fill))
            .push(widget::button::standard(t("wizard.back")).on_press(Message::Close))
            .align_y(Alignment::Center);
        let columns = widget::row::with_capacity(3)
            .push(widget::container(sections).width(Length::Fixed(180.0)))
            .push(widget::divider::vertical::default())
            .push(
                widget::scrollable(body)
                    .width(Length::Fill)
                    .height(Length::Fill),
            )
            .spacing(spacing.space_s)
            .height(Length::Fill);

        let mut root = widget::column::with_capacity(3).push(header).push(columns);
        if let Some(error) = self.error.as_ref() {
            root = root.push(widget::text::caption(error.clone()));
        }
        root.spacing(spacing.space_s)
            .padding(spacing.space_s)
            .into()
    }

    fn general(&self) -> Element<'_, Message> {
        let mut languages = Vec::with_capacity(LANGUAGES.len() + 1);
        languages.push(t("settings.general.languageSystem"));
        languages.extend(LANGUAGES.iter().map(|(_, name)| (*name).to_string()));
        let selected = self.preferences.language.as_deref().map_or(0, |chosen| {
            LANGUAGES
                .iter()
                .position(|(tag, _)| *tag == chosen)
                .map_or(0, |index| index + 1)
        });
        let appearance = widget::settings::section()
            .title(t("settings.general.appearance"))
            .add(
                widget::settings::item::builder(t("settings.general.language")).control(
                    widget::dropdown(languages, Some(selected), |index| {
                        Message::Set(Change::Language(
                            index.checked_sub(1).map(|index| LANGUAGES[index].0),
                        ))
                    }),
                ),
            );
        widget::settings::view_column(vec![appearance.into()]).into()
    }

    fn security(&self) -> Element<'_, Message> {
        let preferences = &self.preferences;
        let auto_lock = widget::settings::section()
            .title(t("settings.autolock"))
            .add(
                widget::settings::item::builder(t("settings.autolockAfter")).control(
                    minutes_choice(AUTO_LOCK_MINUTES, preferences.auto_lock_minutes, |value| {
                        Message::Set(Change::AutoLockMinutes(value))
                    }),
                ),
            )
            .add(
                widget::settings::item::builder(t("settings.lockOnFocusLoss"))
                    .toggler(preferences.lock_on_focus_loss, |value| {
                        Message::Set(Change::LockOnFocusLoss(value))
                    }),
            );
        let clipboard = widget::settings::section()
            .title(t("settings.clipboard"))
            .add(
                widget::settings::item::builder(t("settings.clipboardAfter")).control(
                    seconds_choice(
                        CLIPBOARD_SECONDS,
                        preferences.clipboard_clear_seconds,
                        |value| Message::Set(Change::ClipboardSeconds(value)),
                    ),
                ),
            )
            .add(
                widget::settings::item::builder(t("settings.clipboardOnLock"))
                    .toggler(preferences.clipboard_clear_on_lock, |value| {
                        Message::Set(Change::ClipboardOnLock(value))
                    }),
            )
            .add(
                widget::settings::item::builder(t("settings.clipboardOnExit"))
                    .toggler(preferences.clipboard_clear_on_exit, |value| {
                        Message::Set(Change::ClipboardOnExit(value))
                    }),
            )
            .add(
                widget::settings::item::builder(t("settings.clipboardIfUnchanged"))
                    .toggler(preferences.clipboard_clear_if_unchanged, |value| {
                        Message::Set(Change::ClipboardIfUnchanged(value))
                    }),
            );
        let reveal = widget::settings::section().title(t("settings.reveal")).add(
            widget::settings::item::builder(t("settings.revealAfter")).control(seconds_choice(
                REVEAL_SECONDS,
                preferences.auto_hide_reveal_seconds,
                |value| Message::Set(Change::AutoHideRevealSeconds(value)),
            )),
        );

        let mut sections: Vec<Element<'_, Message>> =
            vec![auto_lock.into(), clipboard.into(), reveal.into()];
        if let Some(unlock) = self.unlock_section() {
            sections.push(unlock);
        }
        widget::settings::view_column(sections).into()
    }

    fn unlock_section(&self) -> Option<Element<'_, Message>> {
        let remembered = self.remembered.as_ref()?;
        let status = match remembered.source.as_str() {
            "hardware_key" => t("settings.unlockSourceHardwareKey"),
            _ if remembered.armed => t("settings.unlockSourceKeystore"),
            _ => t("unlock.placeholder"),
        };
        let mut section = widget::settings::section()
            .title(t("settings.keystore"))
            .add(widget::text::body(status));

        if remembered.hardware_supported {
            for key in &remembered.hardware_keys {
                let mut remove = widget::button::text(t("common.delete"));
                if !self.unlock_busy {
                    remove = remove.on_press(Message::Remove(key.credential_id.clone()));
                }
                section = section.add(
                    widget::settings::item::builder(key.label.clone())
                        .description(key.enrolled_at.clone())
                        .control(remove),
                );
            }
            let mut enroll = widget::button::standard(if self.enrolling {
                t("settings.hardwareKeyTouch")
            } else {
                t("settings.hardwareKeyEnrol")
            });
            if !self.unlock_busy {
                enroll = enroll.on_press(Message::Enroll);
            }
            section = section.add(
                widget::settings::item::builder(t("settings.unlockSourceHardwareKey"))
                    .description(t("settings.hardwareKeyBackupHint"))
                    .control(enroll),
            );
        }

        let mut source = widget::button::standard(if remembered.armed {
            t("settings.forgetDevice")
        } else {
            t("unlock.remember")
        });
        if !self.unlock_busy {
            source = source.on_press(if remembered.armed {
                Message::Forget
            } else {
                Message::UseKeystore
            });
        }
        Some(
            section
                .add(
                    widget::settings::item::builder(t("settings.unlockSourceKeystore"))
                        .control(source),
                )
                .into(),
        )
    }

    fn accounts(&self) -> Element<'_, Message> {
        let mut section =
            widget::settings::section().title(t("settings.accounts.connectedServers"));
        let remotes: Vec<&StorageSummaryFfi> = self
            .storages
            .iter()
            .filter(|storage| storage.kind == "remote")
            .collect();
        if remotes.is_empty() {
            section = section.add(widget::text::body(t("settings.accounts.noServers")));
        }
        for storage in remotes {
            let mut sync = widget::button::standard(t("settings.accounts.syncNow"));
            if !self.syncing {
                sync = sync.on_press(Message::SyncNow(storage.id.clone()));
            }
            section = section.add(
                widget::settings::item::builder(storage.name.clone())
                    .description(storage.id.clone())
                    .control(sync),
            );
        }
        section = section.add(
            widget::settings::item::builder(t("settings.accounts.addServer"))
                .control(widget::button::standard(t("common.create")).on_press(Message::AddServer)),
        );
        widget::settings::view_column(vec![section.into()]).into()
    }

    fn backups(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(16)
            .push(widget::text::title3(t("settings.backups.exportTitle")))
            .spacing(spacing.space_s)
            .width(Length::Fill);

        let mut export = widget::button::standard(if self.busy {
            t("common.loading")
        } else {
            t("settings.backups.exportAction")
        });
        if !self.busy {
            export = export.on_press(Message::Export);
        }
        column = column.push(export);
        if let Some(report) = self.exported.as_ref() {
            column = column.push(widget::text::caption(format!(
                "{} items written to {}",
                report.items_count, report.path
            )));
        } else {
            column = column.push(widget::text::caption(t(
                "settings.backups.plainWarningDesc",
            )));
        }

        column = column
            .push(widget::text::title3("Snapshots"))
            .push(widget::text::caption(
                "A daily encrypted copy of the vault database for rolling back this device.",
            ));
        let mut snapshot = widget::button::standard(if self.busy {
            t("common.loading")
        } else {
            "Take a snapshot now".to_string()
        });
        if !self.busy {
            snapshot = snapshot.on_press(Message::Snapshot);
        }
        column = column.push(snapshot);

        if self.snapshots.is_empty() {
            column = column.push(widget::text::caption("No snapshots yet."));
        } else if let Some(confirming) = self.confirming.as_ref() {
            column = column
                .push(widget::text::body(format!(
                    "Restore the snapshot from {}? Everything added or changed since then is removed from this device.",
                    confirming.created_at
                )))
                .push(widget::text::caption(
                    "The current vault is snapshotted first, so this restore can be undone.",
                ))
                .push(
                    widget::row::with_capacity(2)
                        .push(
                            widget::button::destructive("Restore")
                                .on_press(Message::ConfirmRestore(confirming.path.clone())),
                        )
                        .push(
                            widget::button::standard(t("common.cancel"))
                                .on_press(Message::CancelRestore),
                        )
                        .spacing(spacing.space_xs),
                );
        } else {
            for entry in self.snapshots.iter().take(5) {
                let mut restore = widget::button::text("Restore");
                if !self.busy {
                    restore = restore.on_press(Message::AskRestore(Box::new(entry.clone())));
                }
                column = column.push(
                    widget::row::with_capacity(2)
                        .push(
                            widget::text::caption(format!(
                                "{} · {} KiB",
                                entry.created_at,
                                entry.size_bytes / 1024
                            ))
                            .width(Length::Fill),
                        )
                        .push(restore)
                        .align_y(Alignment::Center),
                );
            }
            column = column.push(widget::text::caption(format!(
                "With Zann closed everywhere, a snapshot and its .identity.json can also be copied over {}",
                self.restore_target
            )));
        }

        column = column.push(widget::text::title3("Integrity"));
        let mut verify = widget::button::standard(if self.busy {
            t("common.loading")
        } else {
            "Check every item".to_string()
        });
        if !self.busy {
            verify = verify.on_press(Message::Verify);
        }
        column = column.push(verify);
        match self.verified.as_ref() {
            None => {
                column = column.push(widget::text::caption(
                    "Decrypts every item and compares its checksum.",
                ));
            }
            Some(report) if report.problems.is_empty() && report.database_ok => {
                column = column.push(widget::text::caption(format!(
                    "All {} items in {} vault(s) are intact.",
                    report.items_ok, report.vaults_checked
                )));
            }
            Some(report) => {
                column = column.push(widget::text::caption(format!(
                    "{} of {} items readable · {} problem(s) found",
                    report.items_ok,
                    report.items_checked,
                    report.problems.len()
                )));
                for problem in report.problems.iter().take(5) {
                    column = column.push(widget::text::caption(format!(
                        "{} — {}",
                        problem.item_path.clone().unwrap_or_else(|| problem
                            .vault_name
                            .clone()
                            .unwrap_or_else(|| "database".to_string())),
                        problem.kind
                    )));
                }
            }
        }
        column.into()
    }

    fn about(&self) -> Element<'_, Message> {
        let logs = self.data_root.join("logs");
        let app = widget::settings::section()
            .title("zann")
            .add(
                widget::settings::item::builder(t("settings.about.version"))
                    .control(widget::text::monotext(env!("CARGO_PKG_VERSION"))),
            )
            .add(
                widget::settings::item::builder(t("settings.about.openDataFolder"))
                    .description(self.data_root.display().to_string())
                    .control(
                        widget::button::standard(t("common.open"))
                            .on_press(Message::Open(self.data_root.display().to_string())),
                    ),
            )
            .add(
                widget::settings::item::builder(t("settings.about.viewLogs")).control(
                    widget::button::standard(t("common.open"))
                        .on_press(Message::Open(logs.display().to_string())),
                ),
            );
        let links = widget::settings::section()
            .title(t("settings.about.links"))
            .add(
                widget::settings::item::builder(t("settings.about.documentation")).control(
                    widget::button::standard(t("common.open"))
                        .on_press(Message::Open(DOCS_URL.into())),
                ),
            )
            .add(
                widget::settings::item::builder(t("settings.about.sourceCode")).control(
                    widget::button::standard(t("common.open"))
                        .on_press(Message::Open(SOURCE_URL.into())),
                ),
            );
        widget::settings::view_column(vec![app.into(), links.into()]).into()
    }
}

fn section_icon(section: SettingsSection) -> &'static str {
    match section {
        SettingsSection::General => "preferences-system-symbolic",
        SettingsSection::Security => "channel-secure-symbolic",
        SettingsSection::Accounts => "system-users-symbolic",
        SettingsSection::Backups => "document-save-symbolic",
        SettingsSection::About => "help-about-symbolic",
    }
}

fn minutes_choice(
    options: &'static [u32],
    selected: u32,
    on_select: fn(u32) -> Message,
) -> Element<'static, Message> {
    let labels = options
        .iter()
        .map(|value| match value {
            0 => t("time.never"),
            60 => t("time.hour"),
            value => format!("{value} {}", t("time.minutes")),
        })
        .collect();
    choice(options, labels, selected, on_select)
}

fn seconds_choice(
    options: &'static [u32],
    selected: u32,
    on_select: fn(u32) -> Message,
) -> Element<'static, Message> {
    let labels = options
        .iter()
        .map(|value| match value {
            0 => t("time.never"),
            120 => format!("2 {}", t("time.minutes")),
            300 => format!("5 {}", t("time.minutes")),
            value => format!("{value} {}", t("time.seconds")),
        })
        .collect();
    choice(options, labels, selected, on_select)
}

fn choice(
    options: &'static [u32],
    labels: Vec<String>,
    selected: u32,
    on_select: fn(u32) -> Message,
) -> Element<'static, Message> {
    let index = options.iter().position(|value| *value == selected);
    widget::dropdown(labels, index, move |index| on_select(options[index])).into()
}
