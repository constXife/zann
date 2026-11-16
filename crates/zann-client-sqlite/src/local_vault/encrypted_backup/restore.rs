use super::*;
impl LocalVault {
    pub fn backup_open_encrypted(
        &self,
        path: String,
        slot: u32,
        recipient: BackupRecipient,
        operation: SessionOperation,
    ) -> LocalResult<BackupHandle> {
        let lease = self.archive_lease(operation)?;
        let _active = self.syncs.register(
            lease.operation.operation_id(),
            lease.operation.cancellation_handle(),
        );
        let mut file = std::fs::File::open(&path).map_err(BackupError::source)?;
        let header = ArchiveHeader::read(&mut file).map_err(crypto)?;
        let descriptor = header
            .recipients()
            .get(slot as usize)
            .ok_or_else(|| failure(BackupFailure::RecipientMissing))?;
        let key = self.unlock_backup_recipient(descriptor, &recipient)?;
        let unlocked = Arc::new(header.unlock(&key).map_err(crypto)?);
        let input = BackupInput::encrypted(
            PathBuf::from(path),
            unlocked,
            lease.operation.clone(),
            (
                self.context_generation.clone(),
                lease.generation,
                lease.expires,
            ),
        );
        // Authenticate every frame, including final marker/EOF, before admitting
        // this source for inspection or any canonical restore mutation.
        let mut reader = input.open().map_err(BackupError::source)?;
        std::io::copy(&mut reader, &mut std::io::sink()).map_err(BackupError::source)?;
        self.save_archive(lease, ArchiveContent::Opened(input))
    }
    pub fn backup_inspect_encrypted(&self, handle: BackupHandle) -> LocalResult<BackupInspection> {
        let (lease, content) = self.archive_snapshot(&handle)?;
        let ArchiveContent::Opened(input) = content else {
            return Err(failure(BackupFailure::HandleKind));
        };
        let _active = self.syncs.register(
            lease.operation.operation_id(),
            lease.operation.cancellation_handle(),
        );
        let result = crate::maintenance::backup::inspect(&input)?;
        let _context = self.context_gate.read().expect("context");
        lease.check(self)?;
        Ok(result)
    }
    pub fn backup_import_encrypted(
        &self,
        handle: BackupHandle,
        source_storage_id: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport> {
        let (work, _active) = self.take_archive(&handle)?;
        let _completion = CompleteArchive(work.lease.operation.clone());
        let ArchiveContent::Opened(input) = work.content else {
            return Err(failure(BackupFailure::HandleKind));
        };
        self.backup_import_input(input, source_storage_id, options, work.lease.operation)
    }
}
