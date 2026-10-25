//! Does the vault still hold what it claims to hold?
//!
//! Snapshots and exports both assume the data is intact when they run. Nothing
//! checked that. This walks the whole vault and answers the question directly,
//! which turns "something might have quietly rotted" into a fact either way.
//!
//! Two layers, because they fail differently:
//!
//! 1. **The database.** `PRAGMA integrity_check` catches a damaged file — bad
//!    pages, a broken index, a torn write.
//! 2. **The payloads.** Every item is checksummed and decrypted. A checksum
//!    mismatch means the stored bytes changed under us; a decryption failure
//!    means they changed in a way the AEAD caught, or the wrong key is in play.
//!    Both are reported, because which one fired says what went wrong.
//!
//! Vault keys are unwrapped through `LocalServices::decrypt_vault_key` rather
//! than reimplemented here — `key_wrap_type` has one meaning and it lives in
//! `zann-db`.

use std::sync::Arc;

use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_db::local::{LocalItemRepo, LocalStorageRepo, LocalVaultRepo};
use zann_db::services::LocalServices;
use zann_db::SqlitePool;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct VerifyError {
    pub kind: String,
    pub message: String,
}

impl VerifyError {
    fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

/// What went wrong with one item, one vault, or the file itself.
#[derive(Debug, Clone)]
pub struct VerifyProblem {
    /// `database`, `vault_key_unusable`, `checksum_mismatch`, `decrypt_failed`
    /// or `read_failed`. Stable; the message is not.
    pub kind: String,
    pub vault_id: Option<String>,
    pub vault_name: Option<String>,
    pub item_id: Option<String>,
    pub item_path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    pub database_ok: bool,
    pub vaults_checked: u64,
    /// Vaults this master key is not meant to open. Not a fault — a remote
    /// vault whose key was never wrapped locally simply cannot be read here,
    /// and calling that corruption would cry wolf.
    pub vaults_skipped: u64,
    pub items_checked: u64,
    pub items_ok: u64,
    pub problems: Vec<VerifyProblem>,
}

impl VerifyReport {
    /// Nothing to act on.
    pub fn is_clean(&self) -> bool {
        self.database_ok && self.problems.is_empty()
    }
}

/// `PRAGMA integrity_check` returns a single `ok` row when the file is sound,
/// and one row per fault when it is not.
async fn check_database(pool: &SqlitePool) -> Result<Vec<String>, VerifyError> {
    zann_db::local::maintenance::integrity_faults(pool)
        .await
        .map_err(|err| VerifyError::new("verify_failed", err.to_string()))
}

/// Walk every vault this key can open and check every item in it.
///
/// Deleted items are checked too: trash is still the user's data, and an
/// unreadable item there is just as much a fault.
pub async fn run(
    pool: &SqlitePool,
    master_key: Arc<SecretKey>,
) -> Result<VerifyReport, VerifyError> {
    let mut report = VerifyReport::default();

    let faults = check_database(pool).await?;
    report.database_ok = faults.is_empty();
    for fault in faults {
        report.problems.push(VerifyProblem {
            kind: "database".to_string(),
            vault_id: None,
            vault_name: None,
            item_id: None,
            item_path: None,
            detail: fault,
        });
    }

    let services = LocalServices::new(pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(pool);
    let vault_repo = LocalVaultRepo::new(pool);
    let item_repo = LocalItemRepo::new(pool);

    let storages = storage_repo
        .list()
        .await
        .map_err(|err| VerifyError::new("verify_failed", err.to_string()))?;

    for storage in storages {
        let vaults = vault_repo
            .list_by_storage(storage.id)
            .await
            .map_err(|err| VerifyError::new("verify_failed", err.to_string()))?;

        for vault in vaults {
            let vault_key = match services.decrypt_vault_key(&vault) {
                Ok(key) => key,
                Err(err) => {
                    report.vaults_skipped += 1;
                    report.problems.push(VerifyProblem {
                        kind: "vault_key_unusable".to_string(),
                        vault_id: Some(vault.id.to_string()),
                        vault_name: Some(vault.name.clone()),
                        item_id: None,
                        item_path: None,
                        detail: err.message,
                    });
                    continue;
                }
            };
            report.vaults_checked += 1;

            let items = item_repo
                .list_by_vault(storage.id, vault.id, true)
                .await
                .map_err(|err| VerifyError::new("verify_failed", err.to_string()))?;

            for item in items {
                // A tombstone keeps no payload, so there is nothing to check
                // and its absence is not a fault.
                if item.payload_enc.is_empty() {
                    continue;
                }
                report.items_checked += 1;

                let checksum = core_crypto::payload_checksum(&item.payload_enc);
                if checksum != item.checksum {
                    report.problems.push(VerifyProblem {
                        kind: "checksum_mismatch".to_string(),
                        vault_id: Some(vault.id.to_string()),
                        vault_name: Some(vault.name.clone()),
                        item_id: Some(item.id.to_string()),
                        item_path: Some(item.path.clone()),
                        detail: format!("stored {}, computed {}", item.checksum, checksum),
                    });
                    continue;
                }

                // The checksum only proves the bytes are the bytes. Decryption
                // proves they are still the item, under the right key.
                if let Err(err) = core_crypto::decrypt_payload_bytes(
                    &vault_key,
                    vault.id,
                    item.id,
                    &item.payload_enc,
                ) {
                    report.problems.push(VerifyProblem {
                        kind: "decrypt_failed".to_string(),
                        vault_id: Some(vault.id.to_string()),
                        vault_name: Some(vault.name.clone()),
                        item_id: Some(item.id.to_string()),
                        item_path: Some(item.path.clone()),
                        detail: err.to_string(),
                    });
                    continue;
                }

                report.items_ok += 1;
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
#[path = "../../tests/maintenance/verify.rs"]
mod tests;
