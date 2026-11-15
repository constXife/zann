//! Coarse archive operations; native handles retain keys, Swift receives summaries.
use crate::{
    BackupExportReport, BackupImportOptions, BackupImportReport, CoreError, CoreFacade, CoreResult,
    SessionOperationFfi,
};
use std::sync::{Arc, Mutex};
use zann_client::app::local as native;

#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum BackupRecipientKindFfi {
    Passphrase,
    Hardware,
    Biometric,
}
#[derive(uniffi::Record)]
pub struct BackupRecipientFfi {
    pub kind: BackupRecipientKindFfi,
    pub passphrase: Option<String>,
    pub pin: Option<String>,
    pub built_in_uv: bool,
}
impl std::fmt::Debug for BackupRecipientFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupRecipientFfi(<redacted>)")
    }
}
impl BackupRecipientFfi {
    fn into_native(self) -> CoreResult<native::BackupRecipient> {
        let mut phrase = zeroize::Zeroizing::new(self.passphrase);
        let mut pin = zeroize::Zeroizing::new(self.pin);
        match self.kind {
            BackupRecipientKindFfi::Passphrase if pin.is_none() && !self.built_in_uv => {
                Ok(native::BackupRecipient::Passphrase {
                    passphrase: phrase.take().ok_or_else(|| {
                        CoreError::InvalidArgument("backup passphrase required".into())
                    })?,
                })
            }
            BackupRecipientKindFfi::Hardware if phrase.is_none() => {
                Ok(native::BackupRecipient::Hardware {
                    pin: pin.take(),
                    built_in_uv: self.built_in_uv,
                })
            }
            BackupRecipientKindFfi::Biometric
                if phrase.is_none() && pin.is_none() && !self.built_in_uv =>
            {
                Ok(native::BackupRecipient::Biometric)
            }
            _ => Err(CoreError::InvalidArgument(
                "invalid backup recipient arguments".into(),
            )),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct BackupRecipientSummaryFfi {
    pub index: u32,
    pub kind: BackupRecipientKindFfi,
}
impl From<native::BackupRecipientKind> for BackupRecipientKindFfi {
    fn from(kind: native::BackupRecipientKind) -> Self {
        match kind {
            native::BackupRecipientKind::Passphrase => Self::Passphrase,
            native::BackupRecipientKind::Hardware => Self::Hardware,
            native::BackupRecipientKind::Biometric => Self::Biometric,
        }
    }
}
impl From<native::BackupRecipientSummary> for BackupRecipientSummaryFfi {
    fn from(value: native::BackupRecipientSummary) -> Self {
        Self {
            index: value.index,
            kind: value.kind.into(),
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct BackupSourceStorageFfi {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct BackupInspectionFfi {
    pub storages: Vec<BackupSourceStorageFfi>,
    pub vaults_count: u64,
    pub items_count: u64,
}
#[derive(uniffi::Object)]
pub struct BackupHandleFfi(Mutex<Option<native::BackupHandle>>);
impl BackupHandleFfi {
    fn get(&self) -> CoreResult<native::BackupHandle> {
        self.0
            .lock()
            .expect("backup handle")
            .clone()
            .ok_or_else(|| CoreError::Service(native::BackupFailure::HandleInvalid.to_string()))
    }
    fn take(&self) -> CoreResult<native::BackupHandle> {
        self.0
            .lock()
            .expect("backup handle")
            .take()
            .ok_or_else(|| CoreError::Service(native::BackupFailure::HandleInvalid.to_string()))
    }
    fn new(handle: native::BackupHandle) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(handle))))
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct BackupCapabilitiesFfi {
    pub recipients: Vec<BackupRecipientKindFfi>,
    pub max_recipients: u32,
}
#[uniffi::export]
impl CoreFacade {
    pub fn backup_capabilities(&self) -> CoreResult<BackupCapabilitiesFfi> {
        let c = self.inner.backup_capabilities()?;
        Ok(BackupCapabilitiesFfi {
            recipients: c.recipients.into_iter().map(Into::into).collect(),
            max_recipients: c.max_recipients,
        })
    }

    pub fn backup_begin(
        &self,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<Arc<BackupHandleFfi>> {
        self.inner
            .backup_begin(operation.take()?)
            .map(BackupHandleFfi::new)
            .map_err(Into::into)
    }
    pub fn backup_add_recipient(
        &self,
        handle: Arc<BackupHandleFfi>,
        recipient: BackupRecipientFfi,
    ) -> CoreResult<BackupRecipientSummaryFfi> {
        self.inner
            .backup_add_recipient(handle.get()?, recipient.into_native()?)
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn backup_export_encrypted(
        &self,
        path: String,
        handle: Arc<BackupHandleFfi>,
    ) -> CoreResult<BackupExportReport> {
        self.inner
            .backup_export_encrypted(path, handle.take()?)
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn backup_encrypted_recipients(
        &self,
        path: String,
    ) -> CoreResult<Vec<BackupRecipientSummaryFfi>> {
        self.inner
            .backup_encrypted_recipients(path)
            .map(|values| values.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }
    pub fn backup_open_encrypted(
        &self,
        path: String,
        slot: u32,
        recipient: BackupRecipientFfi,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<Arc<BackupHandleFfi>> {
        self.inner
            .backup_open_encrypted(path, slot, recipient.into_native()?, operation.take()?)
            .map(BackupHandleFfi::new)
            .map_err(Into::into)
    }
    pub fn backup_inspect_encrypted(
        &self,
        handle: Arc<BackupHandleFfi>,
    ) -> CoreResult<BackupInspectionFfi> {
        self.inner
            .backup_inspect_encrypted(handle.get()?)
            .map(|value| BackupInspectionFfi {
                storages: value
                    .storages
                    .into_iter()
                    .map(|s| BackupSourceStorageFfi {
                        id: s.id,
                        name: s.name,
                    })
                    .collect(),
                vaults_count: value.vaults_count,
                items_count: value.items_count,
            })
            .map_err(Into::into)
    }
    pub fn backup_import_encrypted(
        &self,
        handle: Arc<BackupHandleFfi>,
        source_storage_id: String,
        options: BackupImportOptions,
    ) -> CoreResult<BackupImportReport> {
        self.inner
            .backup_import_encrypted(handle.take()?, source_storage_id, options.into())
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn backup_cancel(&self, handle: Arc<BackupHandleFfi>) -> CoreResult<()> {
        if let Some(handle) = handle.0.lock().expect("backup handle").take() {
            self.inner.backup_cancel(handle)?;
        }
        Ok(())
    }
}
