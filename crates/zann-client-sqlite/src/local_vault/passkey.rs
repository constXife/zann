//! External files are parsed once in Rust; all publication is session-bound.
use super::*;
use exchange::{Credential, ExchangeDocument, ExchangeEntry, ExchangeMetadata};
use std::collections::BTreeMap;
use zann_client::passkey_exchange as exchange;

fn failure(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> LocalError {
    LocalError::Backup {
        kind: "passkey_exchange".into(),
        message: "Passkey exchange failed; no partial import was committed.".into(),
        source: error.into(),
    }
}
fn reject(message: &'static str) -> LocalError {
    LocalError::InvalidArgument(message.into())
}
fn ids(target: &PasskeyTarget) -> LocalResult<(Uuid, Uuid)> {
    let parse = |s: &str| {
        Uuid::parse_str(s)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == s)
            .ok_or_else(|| reject("Select an explicit storage and personal vault."))
    };
    Ok((parse(&target.storage_id)?, parse(&target.vault_id)?))
}
fn admit(batch: &zann_db::services::PreparedItemBatch) -> LocalResult<()> {
    let vault = batch.vault();
    zann_core::item_policy::admit_item_type(
        "passkey",
        vault.kind,
        if vault.key_wrap_type == zann_db::local::KeyWrapType::RemoteServer {
            zann_core::VaultEncryptionType::Server
        } else {
            zann_core::VaultEncryptionType::Client
        },
    )
    .map_err(failure)
}
impl LocalVault {
    pub fn passkey_targets(&self) -> LocalResult<Vec<PasskeyTargetSummary>> {
        let operation =
            SessionOperation::new(std::time::Instant::now() + std::time::Duration::from_secs(120))
                .0;
        let (storage, pool, generation, _active) = {
            let _context = self.context_gate.read().expect("context");
            self.root_key()?;
            (
                self.storage_id()?,
                self.pool(),
                self.context_generation.load(Ordering::SeqCst),
                self.item_reads
                    .register(operation.operation_id(), operation.cancellation_handle()),
            )
        };
        let vaults=self.runtime.block_on(async {let repo=LocalVaultRepo::new(&pool);tokio::select!{biased;
            _=operation.cancelled()=>Err(LocalError::Cancelled),
            _=tokio::time::sleep_until(operation.deadline().into())=>Err(LocalError::DeadlineExceeded),
            result=repo.list_by_storage_bounded(storage)=>result.map_err(failure),
        }})?;
        let _context = self.context_gate.read().expect("context");
        self.check_context_generation(generation)?;
        Ok(vaults
            .into_iter()
            .filter(|vault| {
                vault.kind == zann_core::VaultKind::Personal
                    && vault.key_wrap_type != zann_db::local::KeyWrapType::RemoteServer
            })
            .map(|vault| PasskeyTargetSummary {
                target: PasskeyTarget {
                    storage_id: storage.to_string(),
                    vault_id: vault.id.to_string(),
                },
                name: vault.name,
            })
            .collect())
    }

    pub fn passkey_preflight_file(
        &self,
        path: String,
        format: PasskeyExchangeFormat,
    ) -> LocalResult<PasskeyImportPreview> {
        let document = exchange::import(
            exchange::open_regular_input(Path::new(&path)).map_err(failure)?,
            format,
        )
        .map_err(failure)?;
        Ok(PasskeyImportPreview {
            credentials: document.credential_count() as u64,
            items: document.entries.len() as u64,
            ignored_records: document.ignored_records,
        })
    }
    pub fn passkey_import_file(
        &self,
        path: String,
        format: PasskeyExchangeFormat,
        target: PasskeyTarget,
        operation: SessionOperation,
    ) -> LocalResult<PasskeyImportReport> {
        let (storage, vault) = ids(&target)?;
        let (generation, _active) = {
            let _context = self.context_gate.read().expect("context");
            self.root_key()?;
            super::item_read::check_active(&operation)?;
            (
                self.context_generation.load(Ordering::SeqCst),
                self.syncs
                    .register(operation.operation_id(), operation.cancellation_handle()),
            )
        };
        let document = exchange::import(
            exchange::open_regular_input(Path::new(&path)).map_err(failure)?,
            format,
        )
        .map_err(failure)?;
        let (key, pool) = {
            let _context = self.context_gate.read().expect("context");
            super::item_read::check_active(&operation)?;
            self.check_context_generation(generation)?;
            (self.account_key_for_storage(storage)?, self.pool())
        };
        let _runtime = self.runtime.enter();
        let services = LocalServices::new(&pool, &key);
        let (batch,report)=self.runtime.block_on(async {
            tokio::select! { biased;
                _=operation.cancelled()=>Err(LocalError::Cancelled),
                _=tokio::time::sleep_until(operation.deadline().into())=>Err(LocalError::DeadlineExceeded),
                result=prepare_import(&services,storage,vault,&document,&operation)=>result,
            }
        })?;
        // A canceled preparation drops its transaction. Once commit starts its
        // result is awaited under the final context lease, never detached/retried.
        let _context = self.context_gate.read().expect("context");
        super::item_read::check_active(&operation)?;
        self.check_context_generation(generation)?;
        self.runtime.block_on(batch.commit()).map_err(failure)?;
        Ok(report)
    }
    pub fn passkey_export_cxf(
        &self,
        path: String,
        target: PasskeyTarget,
        authorization: ExportAuthorization,
    ) -> LocalResult<BackupExportReport> {
        let (record, _active) = self.consume_export(authorization)?;
        let (storage, vault) = ids(&target)?;
        let (key, pool) = {
            let _context = self.context_gate.read().expect("context");
            record.check(self)?;
            (self.account_key_for_storage(storage)?, self.pool())
        };
        let services = LocalServices::new(&pool, &key);
        let document=self.runtime.block_on(async {
            tokio::select! { biased;
                _=record.operation.cancelled()=>Err(LocalError::Cancelled),
                _=tokio::time::sleep_until(record.expires.into())=>Err(ExportError::AuthorizationExpired.into()),
                result=export_document(&services,storage,vault,&record.operation,record.expires)=>result,
            }
        })?;
        record.check_persisted(self)?;
        let mut output = super::output::CheckedOutput::new(self, record, Path::new(&path))?;
        exchange::write_cxf(
            &mut output,
            &document,
            exchange::CxfExportContext {
                timestamp: chrono::Utc::now(),
                account_id: storage.as_bytes(),
                username: "",
                email: "",
            },
        )
        .map_err(failure)?;
        output.lease.check_persisted(self)?;
        output.publish()?;
        Ok(BackupExportReport {
            path,
            storages_count: 1,
            vaults_count: 1,
            items_count: document.credential_count() as u64,
        })
    }
}
async fn prepare_import(
    services: &LocalServices<'_>,
    storage: Uuid,
    vault: Uuid,
    document: &ExchangeDocument,
    operation: &SessionOperation,
) -> LocalResult<(zann_db::services::PreparedItemBatch, PasskeyImportReport)> {
    let mut batch = services
        .begin_item_batch(storage, vault)
        .await
        .map_err(failure)?;
    admit(&batch)?;
    let rows = batch
        .read_type(
            "passkey",
            exchange::MAX_EXCHANGE_ENTRIES,
            exchange::MAX_EXCHANGE_BYTES,
        )
        .await
        .map_err(failure)?;
    let mut existing = BTreeMap::new();
    for (_, payload) in rows {
        super::item_read::check_active(operation)?;
        let credential = Credential::from_payload(&payload).map_err(failure)?;
        if existing.insert(credential.identity(), credential).is_some() {
            return Err(reject("The target contains duplicate passkeys."));
        }
    }
    let import_id = Uuid::now_v7();
    let mut report = PasskeyImportReport {
        imported: 0,
        skipped_existing: 0,
    };
    for (entry_index, entry) in document.entries.iter().enumerate() {
        for (index, credential) in entry.credentials.iter().enumerate() {
            super::item_read::check_active(operation)?;
            if let Some(previous) = existing.get(&credential.identity()) {
                if previous.public_key() != credential.public_key()
                    || previous.user_handle() != credential.user_handle()
                {
                    return Err(reject(
                        "A passkey identity conflicts with the target vault.",
                    ));
                }
                report.skipped_existing += 1;
                continue;
            }
            let suffix = if entry.credentials.len() > 1 {
                format!(" ({})", index + 1)
            } else {
                String::new()
            };
            let path = format!("Passkeys/{import_id}/{entry_index}/{}{suffix}", entry.title);
            let payload = entry.payload(index).map_err(failure)?;
            batch
                .add(
                    path,
                    "passkey".into(),
                    payload,
                    zann_core::ItemMetadata {
                        favorite: entry.favorite,
                        tags: Some(entry.tags.clone()),
                    },
                )
                .await
                .map_err(failure)?;
            report.imported += 1;
        }
    }
    Ok((batch, report))
}
async fn export_document(
    services: &LocalServices<'_>,
    storage: Uuid,
    vault: Uuid,
    operation: &SessionOperation,
    expires: std::time::Instant,
) -> LocalResult<ExchangeDocument> {
    let mut batch = services
        .begin_item_batch(storage, vault)
        .await
        .map_err(failure)?;
    admit(&batch)?;
    let rows = batch
        .read_type(
            "passkey",
            exchange::MAX_EXCHANGE_ENTRIES,
            exchange::MAX_EXCHANGE_BYTES,
        )
        .await
        .map_err(failure)?;
    let mut document = ExchangeDocument::new();
    for (item, payload) in rows {
        super::item_read::check_active(operation)?;
        if std::time::Instant::now() >= expires {
            return Err(ExportError::AuthorizationExpired.into());
        }
        let credential = Credential::from_payload(&payload).map_err(failure)?;
        let metadata = ExchangeMetadata::from_payload(&payload).map_err(failure)?;
        let title = metadata.title.as_ref().unwrap_or(&item.name).clone();
        let item_metadata = item
            .metadata
            .ok_or_else(|| reject("Refresh item metadata before exporting."))?;
        document.entries.push(ExchangeEntry {
            id: item.id.as_bytes().to_vec(),
            title,
            credentials: vec![credential],
            metadata,
            favorite: item_metadata.favorite,
            tags: item_metadata.tags.unwrap_or_default(),
        });
    }
    batch.commit().await.map_err(failure)?;
    Ok(document)
}

#[cfg(test)]
mod tests;
