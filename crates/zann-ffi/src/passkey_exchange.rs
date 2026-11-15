//! File-only passkey projection: private keys stay inside the native service.
use crate::export::ExportAuthorizationFfi;
use crate::{BackupExportReport, CoreFacade, CoreResult, SessionOperationFfi};
use std::sync::Arc;
use zann_client::app::local as native;
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum PasskeyExchangeFormatFfi {
    Cxf,
    Bitwarden,
    KeepassXcPasskey,
    KeepassXml,
}
impl From<PasskeyExchangeFormatFfi> for native::PasskeyExchangeFormat {
    fn from(value: PasskeyExchangeFormatFfi) -> Self {
        match value {
            PasskeyExchangeFormatFfi::Cxf => Self::Cxf,
            PasskeyExchangeFormatFfi::Bitwarden => Self::Bitwarden,
            PasskeyExchangeFormatFfi::KeepassXcPasskey => Self::KeepassXcPasskey,
            PasskeyExchangeFormatFfi::KeepassXml => Self::KeepassXml,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyTargetFfi {
    pub storage_id: String,
    pub vault_id: String,
}
impl From<PasskeyTargetFfi> for native::PasskeyTarget {
    fn from(value: PasskeyTargetFfi) -> Self {
        Self {
            storage_id: value.storage_id,
            vault_id: value.vault_id,
        }
    }
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyImportPreviewFfi {
    pub credentials: u64,
    pub items: u64,
    pub ignored_records: u64,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyImportReportFfi {
    pub imported: u64,
    pub skipped_existing: u64,
}
#[derive(Clone, Debug, uniffi::Record)]
pub struct PasskeyTargetSummaryFfi {
    pub target: PasskeyTargetFfi,
    pub name: String,
}
#[uniffi::export]
impl CoreFacade {
    pub fn passkey_targets(&self) -> CoreResult<Vec<PasskeyTargetSummaryFfi>> {
        Ok(self
            .inner
            .passkey_targets()?
            .into_iter()
            .map(|value| PasskeyTargetSummaryFfi {
                target: PasskeyTargetFfi {
                    storage_id: value.target.storage_id,
                    vault_id: value.target.vault_id,
                },
                name: value.name,
            })
            .collect())
    }

    pub fn passkey_preflight_file(
        &self,
        path: String,
        format: PasskeyExchangeFormatFfi,
    ) -> CoreResult<PasskeyImportPreviewFfi> {
        let value = self.inner.passkey_preflight_file(path, format.into())?;
        Ok(PasskeyImportPreviewFfi {
            credentials: value.credentials,
            items: value.items,
            ignored_records: value.ignored_records,
        })
    }
    pub fn passkey_import_file(
        &self,
        path: String,
        format: PasskeyExchangeFormatFfi,
        target: PasskeyTargetFfi,
        operation: Arc<SessionOperationFfi>,
    ) -> CoreResult<PasskeyImportReportFfi> {
        let value = self.inner.passkey_import_file(
            path,
            format.into(),
            target.into(),
            operation.take()?,
        )?;
        Ok(PasskeyImportReportFfi {
            imported: value.imported,
            skipped_existing: value.skipped_existing,
        })
    }
    pub fn passkey_export_cxf(
        &self,
        path: String,
        target: PasskeyTargetFfi,
        authorization: Arc<ExportAuthorizationFfi>,
    ) -> CoreResult<BackupExportReport> {
        Ok(self
            .inner
            .passkey_export_cxf(path, target.into(), authorization.take()?)?
            .into())
    }
}
