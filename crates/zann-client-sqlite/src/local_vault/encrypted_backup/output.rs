use super::*;
use zann_crypto::backup::ArchiveWriter;
impl super::super::output::OutputLease for ArchiveLease {
    fn check_output(&self, core: &LocalVault) -> LocalResult<()> {
        self.check(core)
    }
}
impl LocalVault {
    pub fn backup_export_encrypted(
        &self,
        path: String,
        handle: BackupHandle,
    ) -> LocalResult<BackupExportReport> {
        let (work, _active) = self.take_archive(&handle)?;
        let _completion = CompleteArchive(work.lease.operation.clone());
        let ArchiveContent::Prepared(keys) = work.content else {
            return Err(failure(BackupFailure::HandleKind));
        };
        if !keys.iter().any(|key| key.descriptor().portable()) {
            return Err(failure(BackupFailure::PortableRecipientRequired));
        }
        if path.trim().is_empty() {
            return Err(failure(BackupFailure::DestinationRequired));
        }
        let target = PathBuf::from(path);
        let ctx = {
            let _context = self.context_gate.read().expect("context");
            work.lease.check(self)?;
            self.backup_ctx()?
        };
        let output = super::super::output::CheckedOutput::new(self, work.lease.clone(), &target)?;
        let mut writer =
            ArchiveWriter::new(output, keys.iter().map(Arc::as_ref)).map_err(crypto)?;
        let report=self.runtime.block_on(async {
            tokio::select! {
                biased;
                _=work.lease.operation.cancelled()=>Err(LocalError::Cancelled),
                _=tokio::time::sleep_until(tokio::time::Instant::from_std(work.lease.expires))=>Err(LocalError::DeadlineExceeded),
                report=crate::maintenance::backup::export_to_writer(&ctx,&mut writer)=>report.map_err(Into::into),
            }
        })?;
        writer.finish().map_err(crypto)?.publish()?;
        Ok(BackupExportReport {
            path: target.display().to_string(),
            storages_count: report.storages_count as u64,
            vaults_count: report.vaults_count as u64,
            items_count: report.items_count as u64,
        })
    }
}
