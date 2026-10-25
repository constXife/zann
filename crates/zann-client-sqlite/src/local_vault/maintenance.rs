use super::*;

impl LocalVault {
    /// Import a plain backup. Pass an empty `path` and it fails rather than
    /// guessing: unlike export there is no sensible default to fall back on.
    pub fn backup_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> LocalResult<BackupImportReport> {
        let ctx = self.backup_ctx()?;
        let path = path.trim();
        if path.is_empty() {
            return Err(LocalError::InvalidArgument(
                "backup path is empty".to_string(),
            ));
        }
        let outcome = self
            .runtime
            .block_on(crate::maintenance::backup::plain_import(
                &ctx,
                PathBuf::from(path),
                options.target_storage_id,
            ))?;
        match outcome {
            crate::maintenance::ImportOutcome::Done(report) => Ok(BackupImportReport {
                imported_items: report.imported_items as u64,
                skipped_existing: report.skipped_existing as u64,
                skipped_missing_storage: report.skipped_missing_storage as u64,
                skipped_missing_vault: report.skipped_missing_vault as u64,
                skipped_deleted: report.skipped_deleted as u64,
            }),
            crate::maintenance::ImportOutcome::NeedsRemote(_) => Err(LocalError::Unimplemented(
                "backup import into a remote storage".to_string(),
            )),
        }
    }

    /// Inspect an Apple Passwords CSV before the UI asks for confirmation.
    /// Secret values are streamed through the parser and are not retained in
    /// the returned summary.
    pub fn apple_passwords_preflight_file(
        &self,
        path: String,
    ) -> LocalResult<ApplePasswordsPreflight> {
        let path = path.trim();
        if path.is_empty() {
            return Err(LocalError::InvalidArgument(
                "Apple Passwords CSV path is empty".to_string(),
            ));
        }
        let report = crate::maintenance::backup::apple_passwords_preflight(Path::new(path))?;
        Ok(ApplePasswordsPreflight {
            total_rows: report.total_rows as u64,
            importable_items: report.importable_items as u64,
            duplicate_rows: report.duplicate_rows as u64,
            invalid_rows: report.invalid_rows as u64,
        })
    }

    /// Import an Apple Passwords CSV into the selected personal vault. Existing
    /// paths and repeated titles are suffixed instead of overwritten or lost.
    pub fn apple_passwords_import_file(
        &self,
        path: String,
        options: BackupImportOptions,
    ) -> LocalResult<ApplePasswordsImportReport> {
        let ctx = self.backup_ctx()?;
        let path = path.trim();
        if path.is_empty() {
            return Err(LocalError::InvalidArgument(
                "Apple Passwords CSV path is empty".to_string(),
            ));
        }
        let report = self
            .runtime
            .block_on(crate::maintenance::backup::apple_passwords_import(
                &ctx,
                PathBuf::from(path),
                options.target_storage_id,
            ))?;
        Ok(ApplePasswordsImportReport {
            imported_items: report.imported_items as u64,
            renamed_items: report.renamed_items as u64,
            skipped_invalid: report.skipped_invalid as u64,
        })
    }

    /// Export every local vault to a plain backup file. An empty `path` writes
    /// to the vault directory's default location, which is what a client with
    /// no file picker of its own wants.
    pub fn backup_export_file(&self, path: String) -> LocalResult<BackupExportReport> {
        let ctx = self.backup_ctx()?;
        let path = path.trim();
        let target = if path.is_empty() {
            ctx.default_export_path()
        } else {
            PathBuf::from(path)
        };
        let report = self
            .runtime
            .block_on(crate::maintenance::backup::plain_export(&ctx, target))?;
        Ok(BackupExportReport {
            path: report.path,
            storages_count: report.storages_count as u64,
            vaults_count: report.vaults_count as u64,
            items_count: report.items_count as u64,
        })
    }

    /// Walk every vault and item this key can open, checking the database
    /// structure, every stored checksum and every payload's decryption.
    ///
    /// Needs the key, unlike a snapshot: proving a payload is still readable
    /// means reading it.
    pub fn verify(&self) -> LocalResult<VerifyReport> {
        let master_key = self.master_key()?;
        let report = self
            .runtime
            .block_on(crate::maintenance::verify::run(&self.pool(), master_key))?;
        Ok(report.into())
    }

    /// Copy the vault database to `<root>/snapshots/`, then apply retention.
    ///
    /// No master key is required, and deliberately so: this copies a file that
    /// is already readable on disk and stays encrypted in the copy, so
    /// demanding an unlock would suggest a protection that is not there.
    pub fn snapshot_create(&self, retention: Option<Retention>) -> LocalResult<Snapshot> {
        let policy = retention.map(Into::into).unwrap_or_default();
        let snapshot = self.runtime.block_on(crate::maintenance::snapshot::create(
            &self.pool(),
            &self.root,
            &policy,
        ))?;
        Ok(snapshot.into())
    }

    /// Take one only if the newest has aged past `max_age_hours`. Returns
    /// `None` when a recent enough snapshot already exists, so a client can call
    /// this on every start without thinking about it.
    pub fn snapshot_create_if_due(
        &self,
        max_age_hours: u32,
        retention: Option<Retention>,
    ) -> LocalResult<Option<Snapshot>> {
        let policy = retention.map(Into::into).unwrap_or_default();
        let max_age = std::time::Duration::from_secs(u64::from(max_age_hours) * 3600);
        let snapshot = self
            .runtime
            .block_on(crate::maintenance::snapshot::create_if_due(
                &self.pool(),
                &self.root,
                max_age,
                &policy,
            ))?;
        Ok(snapshot.map(Into::into))
    }

    /// Newest first.
    pub fn snapshot_list(&self) -> LocalResult<Vec<Snapshot>> {
        Ok(crate::maintenance::snapshot::list(&self.root)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Where a snapshot has to be copied back to, for a client that would
    /// rather show the path than call [`Self::snapshot_restore`] — restoring by
    /// hand with everything closed is still a valid procedure.
    pub fn snapshot_restore_target(&self) -> String {
        crate::maintenance::snapshot::restore_target(&self.root)
            .display()
            .to_string()
    }

    /// Put a snapshot back, without the user having to close anything or copy
    /// files by hand.
    ///
    /// The vault is locked first and stays locked: the restored database may
    /// have been written under a different master key, so the key in memory
    /// cannot be assumed to still open it. Whoever calls this has to unlock
    /// again afterwards, with the password that was in use when the snapshot was
    /// taken.
    ///
    /// A remembered unlock is dropped when the salt came back with the snapshot
    /// — the stored key was derived from the salt that has just been replaced,
    /// so it would fail every unlock until someone thought to clear it.
    pub fn snapshot_restore(&self, path: String) -> LocalResult<SnapshotRestore> {
        let path = PathBuf::from(path);
        // Lock before anything moves. If the restore fails halfway, a locked
        // vault is recoverable; a key held over a database it does not match is
        // a stream of decryption failures nobody can explain.
        *self.master_key.lock().expect("lock poisoned") = None;
        *self.vault_id.lock().expect("lock poisoned") = None;

        let outcome = self.runtime.block_on(crate::maintenance::snapshot::restore(
            self.pool(),
            &self.root,
            &path,
        ));

        // Reopen whatever happened. A restore that failed part-way still closed
        // the pool, and the file it left behind is the one that was already
        // there — so the vault is fine and only this handle is dead. Returning
        // the error without reopening would turn a recoverable failure into a
        // facade that answers nothing until the app restarts.
        let reopened = self.reopen_pool();
        let outcome = outcome?;
        reopened?;

        if outcome.identity_replaced {
            let _ = self.forget_remembered();
        }

        Ok(SnapshotRestore {
            restored_from: outcome.restored_from.display().to_string(),
            replaced_saved_to: outcome.replaced_saved_to.display().to_string(),
            identity_replaced: outcome.identity_replaced,
        })
    }
}
