//! Native archive form; factors, streaming format and restore policy belong to core.
use super::*;
use zann_client::app::local::{
    BackupCapabilities, BackupHandle, BackupInspection, BackupRecipient, BackupRecipientKind,
    BackupRecipientSummary, SessionCancellationHandle, SessionOperation,
};
use zeroize::Zeroize;
mod view;
#[derive(Default)]
pub(super) struct State {
    facade: Option<local::Facade>,
    handle: Option<BackupHandle>,
    cancel: Option<SessionCancellationHandle>,
    generation: u64,
    visible: bool,
    restoring: bool,
    busy: bool,
    exporting: bool,
    capabilities: Option<BackupCapabilities>,
    recipients: Vec<BackupRecipientSummary>,
    kind: usize,
    phrase: String,
    pin: String,
    built_in_uv: bool,
    slot: Option<usize>,
    path: Option<String>,
    inspection: Option<BackupInspection>,
    source: Option<usize>,
    target: Option<usize>,
    targets: Vec<StorageSummary>,
    error: Option<String>,
    report: Option<String>,
}
#[derive(Clone)]
pub enum Effect {
    Prepared(BackupHandle, BackupCapabilities),
    Added(BackupRecipientSummary),
    Source(String, Vec<BackupRecipientSummary>),
    Opened(BackupHandle, BackupInspection, Vec<StorageSummary>),
    Saved(BackupExportReport),
    Imported(u64),
    Cancelled,
}
#[derive(Clone)]
pub enum Message {
    Export,
    Restore,
    Choose,
    Kind(usize),
    Phrase(String),
    Pin(String),
    BuiltInUV(bool),
    Slot(usize),
    Source(usize),
    Target(usize),
    Add,
    Save,
    Unlock,
    Import,
    Cancel,
    Finished(u64, Result<Effect, String>),
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EncryptedBackupMessage(<redacted>)")
    }
}
impl Drop for State {
    fn drop(&mut self) {
        self.cancel();
    }
}
impl State {
    pub(super) fn cancel(&mut self) {
        self.generation += 1;
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        if let (Some(facade), Some(handle)) = (&self.facade, self.handle.take()) {
            if let Err(error) = facade.backup_cancel(handle) {
                self.error = Some(error.to_string());
            }
        }
        self.phrase.zeroize();
        self.pin.zeroize();
        self.visible = false;
        self.busy = false;
        self.exporting = false;
        self.path = None;
        self.inspection = None;
        self.recipients.clear();
        self.slot = None;
        self.source = None;
        self.target = None;
        self.report = None;
        self.capabilities = None;
    }
    fn operation(&mut self) -> SessionOperation {
        let (operation, cancel) =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(600));
        self.cancel = Some(cancel);
        operation
    }
    fn run(
        &mut self,
        work: impl FnOnce() -> Result<Effect, String> + Send + 'static,
    ) -> Task<Message> {
        self.busy = true;
        self.error = None;
        let generation = self.generation;
        cosmic::task::future(async move { Message::Finished(generation, off_thread(work).await) })
    }
    fn recipient(&mut self, kind: BackupRecipientKind) -> BackupRecipient {
        let mut phrase = zeroize::Zeroizing::new(std::mem::take(&mut self.phrase));
        let mut pin = zeroize::Zeroizing::new(std::mem::take(&mut self.pin));
        match kind {
            BackupRecipientKind::Passphrase => BackupRecipient::Passphrase {
                passphrase: std::mem::take(&mut *phrase),
            },
            BackupRecipientKind::Hardware => BackupRecipient::Hardware {
                pin: (!pin.is_empty() && !self.built_in_uv).then(|| std::mem::take(&mut *pin)),
                built_in_uv: self.built_in_uv,
            },
            BackupRecipientKind::Biometric => BackupRecipient::Biometric,
        }
    }
    pub(super) fn update(&mut self, message: Message, session: &Session) -> Task<Message> {
        let facade = session.facade();
        match message {
            Message::Export => {
                self.cancel();
                self.visible = true;
                self.restoring = false;
                self.facade = Some(facade.clone());
                let operation = self.operation();
                return self.run(move || {
                    let caps = facade.backup_capabilities().map_err(|e| e.to_string())?;
                    let handle = facade.backup_begin(operation).map_err(|e| e.to_string())?;
                    Ok(Effect::Prepared(handle, caps))
                });
            }
            Message::Restore => {
                self.cancel();
                self.visible = true;
                self.restoring = true;
                self.facade = Some(facade);
            }
            Message::Choose if !self.busy => {
                self.busy = true;
                self.error = None;
                let generation = self.generation;
                return cosmic::task::future(async move {
                    let result = match file_chooser::open::Dialog::new()
                        .title(t("backup.choose"))
                        .open_file()
                        .await
                    {
                        Ok(response) => match response.url().to_file_path() {
                            Ok(path) => {
                                off_thread(move || {
                                    let path = path.display().to_string();
                                    let rows = facade
                                        .backup_encrypted_recipients(path.clone())
                                        .map_err(|e| e.to_string())?;
                                    Ok(Effect::Source(path, rows))
                                })
                                .await
                            }
                            Err(()) => Err("The selected file has no native path".into()),
                        },
                        Err(file_chooser::Error::Cancelled) => Ok(Effect::Cancelled),
                        Err(error) => Err(error.to_string()),
                    };
                    Message::Finished(generation, result)
                });
            }
            Message::Kind(index) => self.kind = index,
            Message::Phrase(value) => {
                self.phrase.zeroize();
                self.phrase = value;
            }
            Message::Pin(value) => {
                self.pin.zeroize();
                self.pin = value;
            }
            Message::BuiltInUV(value) => self.built_in_uv = value,
            Message::Slot(index) => self.slot = Some(index),
            Message::Source(index) => self.source = Some(index),
            Message::Target(index) => self.target = Some(index),
            Message::Add if !self.busy => {
                if let (Some(handle), Some(kind)) = (
                    self.handle.clone(),
                    self.capabilities
                        .as_ref()
                        .and_then(|c| c.recipients.get(self.kind))
                        .copied(),
                ) {
                    let recipient = self.recipient(kind);
                    return self.run(move || {
                        facade
                            .backup_add_recipient(handle, recipient)
                            .map(Effect::Added)
                            .map_err(|e| e.to_string())
                    });
                }
            }
            Message::Save if !self.busy => {
                if let Some(handle) = self.handle.clone() {
                    self.busy = true;
                    self.exporting = true;
                    self.error = None;
                    let generation = self.generation;
                    return cosmic::task::future(async move {
                        let result = match file_chooser::save::Dialog::new()
                            .title(t("backup.save"))
                            .file_name("zann-backup.zann".into())
                            .save_file()
                            .await
                        {
                            Ok(response) => {
                                match response.url().ok_or(()).and_then(|url| url.to_file_path()) {
                                    Ok(path) => {
                                        off_thread(move || {
                                            facade
                                                .backup_export_encrypted(
                                                    path.display().to_string(),
                                                    handle,
                                                )
                                                .map(Effect::Saved)
                                                .map_err(|e| e.to_string())
                                        })
                                        .await
                                    }
                                    Err(()) => {
                                        Err("The selected destination has no native path".into())
                                    }
                                }
                            }
                            Err(file_chooser::Error::Cancelled) => Ok(Effect::Cancelled),
                            Err(error) => Err(error.to_string()),
                        };
                        Message::Finished(generation, result)
                    });
                }
            }
            Message::Unlock if !self.busy => {
                if let (Some(path), Some(slot)) = (
                    self.path.clone(),
                    self.slot.and_then(|i| self.recipients.get(i)).cloned(),
                ) {
                    let recipient = self.recipient(slot.kind);
                    let operation = self.operation();
                    return self.run(move || {
                        let handle = facade
                            .backup_open_encrypted(path, slot.index, recipient, operation)
                            .map_err(|e| e.to_string())?;
                        match facade.backup_inspect_encrypted(handle.clone()) {
                            Ok(inspection) => Ok(Effect::Opened(
                                handle,
                                inspection,
                                local::storages(&facade)?,
                            )),
                            Err(error) => {
                                let original = error.to_string();
                                facade
                                    .backup_cancel(handle)
                                    .map_err(|cleanup| format!("{original}; cleanup: {cleanup}"))?;
                                Err(original)
                            }
                        }
                    });
                }
            }
            Message::Import if !self.busy => {
                if let (Some(handle), Some(source), Some(target)) = (
                    self.handle.clone(),
                    self.source
                        .and_then(|i| self.inspection.as_ref()?.storages.get(i))
                        .map(|s| s.id.clone()),
                    self.target
                        .and_then(|i| self.targets.get(i))
                        .map(|s| s.id.clone()),
                ) {
                    return self.run(move || {
                        facade
                            .backup_import_encrypted(
                                handle,
                                source,
                                zann_client::app::local::BackupImportOptions {
                                    target_storage_id: Some(target),
                                },
                            )
                            .map(|r| Effect::Imported(r.imported_items))
                            .map_err(|e| e.to_string())
                    });
                }
            }
            Message::Cancel => self.cancel(),
            Message::Finished(generation, result) => {
                if generation != self.generation {
                    if let Ok(Effect::Prepared(handle, _) | Effect::Opened(handle, _, _)) = result {
                        if let Err(error) = facade.backup_cancel(handle) {
                            self.error = Some(error.to_string());
                        }
                    }
                    return Task::none();
                }
                self.busy = false;
                if self.exporting && !matches!(&result, Ok(Effect::Cancelled)) {
                    self.handle = None;
                }
                self.exporting = false;
                match result {
                    Ok(Effect::Prepared(handle, caps)) => {
                        self.handle = Some(handle);
                        self.capabilities = Some(caps);
                        self.kind = 0;
                    }
                    Ok(Effect::Added(summary)) => self.recipients.push(summary),
                    Ok(Effect::Source(path, rows)) => {
                        self.path = Some(path);
                        self.recipients = rows;
                        self.slot = None;
                    }
                    Ok(Effect::Opened(handle, inspection, targets)) => {
                        self.handle = Some(handle);
                        self.inspection = Some(inspection);
                        self.targets = targets;
                    }
                    Ok(Effect::Saved(report)) => {
                        self.handle = None;
                        self.report = Some(report.path);
                    }
                    Ok(Effect::Imported(count)) => {
                        self.handle = None;
                        self.report =
                            Some(t_args("backup.imported", &[("count", &count.to_string())]));
                    }
                    Ok(Effect::Cancelled) => {}
                    Err(error) => self.error = Some(error),
                }
            }
            _ => {}
        }
        Task::none()
    }
}
