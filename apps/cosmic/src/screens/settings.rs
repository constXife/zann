//! Security settings: how this device remembers the unlock.
//!
//! Only one source is ever active. Enrolling a key switches to it, and removing
//! the last key switches back — that rule lives in `zann-keystore`, so this
//! screen shows the result rather than deciding it.

use cosmic::iced::{Alignment, Length, Task};
use cosmic::{theme, widget, Element};
use zann_ffi::{BackupExportReport, RememberedUnlockFfi, SnapshotFfi, VerifyReportFfi};

use crate::backend::local;
use crate::backend::off_thread;
use crate::session::Session;

pub struct State {
    remembered: Option<RememberedUnlockFfi>,
    /// Set while an authenticator is being waited on, so the view can say what
    /// the user is supposed to do with it.
    enrolling: bool,
    busy: bool,
    error: Option<String>,
    /// Result of the last export, kept on screen so the path can be read off
    /// and the file found.
    exported: Option<BackupExportReport>,
    snapshots: Vec<SnapshotFfi>,
    restore_target: String,
    verified: Option<Box<VerifyReportFfi>>,
}

#[derive(Clone, Debug)]
pub enum Message {
    Loaded(Result<RememberedUnlockFfi, String>),
    Enroll,
    Remove(String),
    UseKeystore,
    Forget,
    Export,
    Exported(Result<BackupExportReport, String>),
    Snapshot,
    Snapshots(Result<Vec<SnapshotFfi>, String>),
    Verify,
    Verified(Result<VerifyReportFfi, String>),
    Close,
}

pub enum Outcome {
    None,
    Task(Task<Message>),
    Close,
}

impl State {
    pub fn new() -> Self {
        Self {
            remembered: None,
            enrolling: false,
            busy: false,
            error: None,
            exported: None,
            snapshots: Vec::new(),
            restore_target: String::new(),
            verified: None,
        }
    }

    /// Loading is a plain file read, but it goes through the same worker thread
    /// as everything else so the facade is only touched from one place.
    pub fn load(session: &Session) -> Task<Message> {
        let facade = session.facade();
        let snapshots = session.facade();
        Task::batch([
            cosmic::task::future(async move {
                Message::Loaded(off_thread(move || local::remembered_unlock(&facade)).await)
            }),
            cosmic::task::future(async move {
                Message::Snapshots(off_thread(move || local::snapshots(&snapshots)).await)
            }),
        ])
    }

    pub fn update(&mut self, message: Message, session: &Session) -> Outcome {
        match message {
            Message::Loaded(Ok(remembered)) => {
                self.busy = false;
                self.enrolling = false;
                self.remembered = Some(remembered);
            }

            Message::Loaded(Err(err)) => {
                self.busy = false;
                self.enrolling = false;
                self.error = Some(err);
            }

            Message::Enroll => {
                if self.busy {
                    return Outcome::None;
                }
                let facade = session.facade();
                self.busy = true;
                self.enrolling = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || {
                            local::enroll_hardware_key(&facade, String::new())?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::Remove(credential_id) => {
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
                        off_thread(move || {
                            local::remove_hardware_key(&facade, credential_id)?;
                            local::remembered_unlock(&facade)
                        })
                        .await,
                    )
                }));
            }

            Message::UseKeystore => {
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
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
                let facade = session.facade();
                self.busy = true;
                self.error = None;
                return Outcome::Task(cosmic::task::future(async move {
                    Message::Loaded(
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

            Message::Close => return Outcome::Close,
        }
        Outcome::None
    }

    pub fn view(&self) -> Element<'_, Message> {
        let spacing = theme::spacing();
        let mut column = widget::column::with_capacity(8)
            .push(widget::text::title3("Unlock on this device"))
            .spacing(spacing.space_s)
            .width(Length::Fixed(460.0));

        let Some(remembered) = self.remembered.as_ref() else {
            return super::centered(column.push(widget::text::body("Loading…")));
        };

        column = column.push(widget::text::body(match remembered.source.as_str() {
            "hardware_key" => "Unlocking with a hardware key.",
            _ if remembered.armed => "Unlocking with the system keystore.",
            _ => "This device asks for the master password every time.",
        }));

        if remembered.hardware_supported {
            for key in &remembered.hardware_keys {
                column = column.push(
                    widget::row::with_capacity(2)
                        .push(
                            widget::text::body(format!("{} · {}", key.label, key.enrolled_at))
                                .width(Length::Fill),
                        )
                        .push(
                            widget::button::text("Remove")
                                .on_press(Message::Remove(key.credential_id.clone())),
                        )
                        .align_y(Alignment::Center),
                );
            }

            let mut enroll = widget::button::standard(if self.enrolling {
                "Insert the key and touch it…"
            } else if remembered.hardware_keys.is_empty() {
                "Enrol a hardware key"
            } else {
                "Enrol another key"
            });
            if !self.busy {
                enroll = enroll.on_press(Message::Enroll);
            }
            column = column.push(enroll);

            // Asked once, in the flow, because nobody goes looking for this.
            if remembered.hardware_keys.len() == 1 {
                column = column.push(widget::text::caption(
                    "Add a backup key: if the only one is lost, unlocking falls back to the master password.",
                ));
            }
        } else {
            column = column.push(widget::text::caption(
                "Hardware keys are not supported on this platform yet.",
            ));
        }

        column = if remembered.armed {
            column.push(
                widget::button::text("Ask for the master password every time")
                    .on_press(Message::Forget),
            )
        } else {
            column.push(
                widget::button::text("Remember with the system keystore")
                    .on_press(Message::UseKeystore),
            )
        };

        column = column.push(widget::text::title3("Your data"));
        let mut export = widget::button::standard(if self.busy {
            "Exporting…"
        } else {
            "Export vault to a file"
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
            column = column.push(widget::text::caption(
                "An unencrypted copy of every local vault. Keep it somewhere safe.",
            ));
        }

        column = column.push(widget::text::title3("Snapshots"));
        column = column.push(widget::text::caption(
            "A copy of the vault database, taken once a day. Still encrypted, \
             unlike the export above — good for going back, not for leaving.",
        ));

        let mut snapshot = widget::button::standard(if self.busy {
            "Working…"
        } else {
            "Take a snapshot now"
        });
        if !self.busy {
            snapshot = snapshot.on_press(Message::Snapshot);
        }
        column = column.push(snapshot);

        if self.snapshots.is_empty() {
            column = column.push(widget::text::caption("No snapshots yet."));
        } else {
            for entry in self.snapshots.iter().take(5) {
                column = column.push(widget::text::caption(format!(
                    "{} · {} KiB",
                    entry.created_at,
                    entry.size_bytes / 1024
                )));
            }
            // Restoring is a file copy with every client closed: swapping the
            // database under a live pool is how a working vault becomes a
            // broken one, so the app shows the paths rather than doing it.
            column = column.push(widget::text::caption(format!(
                "To restore: close Zann everywhere, then copy a snapshot (and its \
                 .identity.json, which holds the salt) over {}",
                self.restore_target
            )));
        }

        column = column.push(widget::text::title3("Integrity"));
        let mut verify = widget::button::standard(if self.busy {
            "Working…"
        } else {
            "Check every item"
        });
        if !self.busy {
            verify = verify.on_press(Message::Verify);
        }
        column = column.push(verify);

        match self.verified.as_ref() {
            None => {
                column = column.push(widget::text::caption(
                    "Decrypts every item and compares its checksum, so \"probably fine\" \
                     becomes a yes or a no.",
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
                column = column.push(widget::text::caption(
                    "Restore from a snapshot below, or export what still reads.",
                ));
            }
        }

        if let Some(error) = self.error.as_ref() {
            column = column.push(widget::text::caption(error.clone()));
        }

        super::centered(column.push(widget::button::standard("Back").on_press(Message::Close)))
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
