//! Authorization is rechecked at bounded writes and under the publication lease.
use super::output::CheckedOutput;
use super::*;
use std::io::{BufWriter, Write};

impl LocalVault {
    pub fn backup_export_file(
        &self,
        path: String,
        authorization: ExportAuthorization,
    ) -> LocalResult<BackupExportReport> {
        let (record, _active) = self.consume_export(authorization)?;
        let ctx = {
            let _context = self.context_gate.read().expect("context");
            record.check(self)?;
            self.backup_ctx()?
        };
        let target = if path.trim().is_empty() {
            ctx.default_export_path()
        } else {
            PathBuf::from(path.trim())
        };
        let operation = record.operation.clone();
        let deadline = record.expires;
        let output = CheckedOutput::new(self, record, &target)?;
        let mut writer = BufWriter::new(output);
        let report = self.runtime.block_on(async {
            tokio::select! {
                biased;
                _ = operation.cancelled() => Err(LocalError::Cancelled),
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => Err(ExportError::AuthorizationExpired.into()),
                report = crate::maintenance::backup::export_to_writer(&ctx, &mut writer) => report.map_err(LocalError::from),
            }
        })?;
        writer
            .flush()
            .map_err(crate::maintenance::BackupError::source)?;
        let output = writer
            .into_inner()
            .map_err(|error| crate::maintenance::BackupError::source(error.into_error()))?;

        output.lease.check_persisted(self)?;
        output.publish()?;
        Ok(BackupExportReport {
            path: target.display().to_string(),
            storages_count: report.storages_count as u64,
            vaults_count: report.vaults_count as u64,
            items_count: report.items_count as u64,
        })
    }
}
