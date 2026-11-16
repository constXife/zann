//! Authorization is rechecked at bounded writes and under the publication lease.
use super::*;
use crate::maintenance::private_output::PrivateOutput;
use std::io::{self, BufWriter, Write};

struct ExportOutput<'a> {
    core: &'a LocalVault,
    authorization: export::AuthorizedExport,
    output: PrivateOutput,
}
impl Write for ExportOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let _context = self.core.context_gate.read().expect("context");
        self.authorization
            .check(self.core)
            .map_err(io::Error::other)?;
        self.output.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        let _context = self.core.context_gate.read().expect("context");
        self.authorization
            .check(self.core)
            .map_err(io::Error::other)?;
        self.output.flush()
    }
}
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
        let output = ExportOutput {
            core: self,
            authorization: record,
            output: PrivateOutput::create(&target)
                .map_err(crate::maintenance::BackupError::source)?,
        };
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
        let mut output = writer
            .into_inner()
            .map_err(|error| crate::maintenance::BackupError::source(error.into_error()))?;
        output
            .output
            .seal()
            .map_err(crate::maintenance::BackupError::source)?;
        output.authorization.check_persisted(self)?;
        let _context = self.context_gate.read().expect("context");
        output.authorization.check(self)?;
        output
            .output
            .publish()
            .map_err(crate::maintenance::BackupError::source)?;
        Ok(BackupExportReport {
            path: target.display().to_string(),
            storages_count: report.storages_count as u64,
            vaults_count: report.vaults_count as u64,
            items_count: report.items_count as u64,
        })
    }
}
