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

use sqlx_core::row::Row;
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
    let rows = sqlx_core::query::query("PRAGMA integrity_check")
        .fetch_all(pool)
        .await
        .map_err(|err| VerifyError::new("verify_failed", err.to_string()))?;

    let mut faults = Vec::new();
    for row in rows {
        let value: String = row
            .try_get(0)
            .map_err(|err| VerifyError::new("verify_failed", err.to_string()))?;
        if value != "ok" {
            faults.push(value);
        }
    }
    Ok(faults)
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
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;
    use zann_core::{EncryptedPayload, ItemsService, VaultsService};

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!("zann-verify-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create temp root");
        root
    }

    async fn seeded(root: &Path) -> (SqlitePool, Arc<SecretKey>) {
        let url = format!("sqlite://{}", root.join("local.sqlite").display());
        let pool = zann_db::connect_sqlite_with_max(&url, 2)
            .await
            .expect("connect");
        zann_db::migrate_local(&pool).await.expect("migrate");
        let master_key = Arc::new(SecretKey::generate());
        (pool, master_key)
    }

    /// Create a local vault with one item, the same way the app would.
    async fn seed_item(pool: &SqlitePool, master_key: &SecretKey, value: &str) -> (Uuid, Uuid) {
        let services = LocalServices::new(pool, master_key);
        let vault = services
            .ensure_default_local_personal()
            .await
            .expect("default vault");
        let mut payload = EncryptedPayload::new("kv");
        payload.fields.insert(
            "value".to_string(),
            zann_core::FieldValue {
                kind: zann_core::FieldKind::Text,
                value: value.to_string(),
                meta: None,
            },
        );
        let item_id = services
            .put_item(
                Uuid::nil(),
                vault.id,
                "secrets/one".to_string(),
                "kv".to_string(),
                payload,
            )
            .await
            .expect("create item");
        (vault.id, item_id)
    }

    #[tokio::test]
    async fn a_healthy_vault_verifies_clean() {
        let root = temp_root();
        let (pool, master_key) = seeded(&root).await;
        seed_item(&pool, master_key.as_ref(), "hello").await;

        let report = run(&pool, master_key).await.expect("verify");

        assert!(report.database_ok, "integrity_check reported a fault");
        assert_eq!(report.items_checked, 1);
        assert_eq!(report.items_ok, 1);
        assert!(
            report.is_clean(),
            "unexpected problems: {:?}",
            report.problems
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn an_empty_vault_verifies_clean() {
        let root = temp_root();
        let (pool, master_key) = seeded(&root).await;

        let report = run(&pool, master_key).await.expect("verify");

        assert!(report.is_clean());
        assert_eq!(report.items_checked, 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The case the whole module exists for: bytes changed underneath, and the
    /// stored checksum no longer describes them.
    #[tokio::test]
    async fn a_corrupted_payload_is_caught_as_a_checksum_mismatch() {
        let root = temp_root();
        let (pool, master_key) = seeded(&root).await;
        let (_, item_id) = seed_item(&pool, master_key.as_ref(), "hello").await;

        // `id` is a 16-byte BLOB, so bind the raw bytes — a string here would
        // silently match nothing and the test would pass without testing.
        let affected =
            sqlx_core::query::query("UPDATE items_cache SET payload_enc = ? WHERE id = ?")
                .bind(vec![0u8; 64])
                .bind(item_id.as_bytes().to_vec())
                .execute(&pool)
                .await
                .expect("corrupt the payload")
                .rows_affected();
        assert_eq!(affected, 1, "the test did not actually corrupt anything");

        let report = run(&pool, master_key).await.expect("verify");

        assert!(!report.is_clean(), "corruption went unnoticed");
        assert_eq!(report.items_ok, 0);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].kind, "checksum_mismatch");
        assert_eq!(
            report.problems[0].item_id.as_deref(),
            Some(item_id.to_string().as_str())
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Bytes that are self-consistent but no longer decryptable: the checksum
    /// agrees, so only the AEAD catches it. This is what tells a rewritten
    /// record apart from a damaged one.
    #[tokio::test]
    async fn undecryptable_bytes_with_a_matching_checksum_are_caught_too() {
        let root = temp_root();
        let (pool, master_key) = seeded(&root).await;
        let (_, item_id) = seed_item(&pool, master_key.as_ref(), "hello").await;

        let bogus = vec![7u8; 96];
        let checksum = core_crypto::payload_checksum(&bogus);
        let affected = sqlx_core::query::query(
            "UPDATE items_cache SET payload_enc = ?, checksum = ? WHERE id = ?",
        )
        .bind(bogus)
        .bind(checksum)
        .bind(item_id.as_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("replace the payload")
        .rows_affected();
        assert_eq!(affected, 1, "the test did not actually replace anything");

        let report = run(&pool, master_key).await.expect("verify");

        assert!(!report.is_clean());
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].kind, "decrypt_failed");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A vault this key cannot open is skipped, not reported as damage.
    #[tokio::test]
    async fn a_vault_belonging_to_another_key_is_skipped_not_failed() {
        let root = temp_root();
        let (pool, master_key) = seeded(&root).await;
        seed_item(&pool, master_key.as_ref(), "hello").await;

        let stranger = Arc::new(SecretKey::generate());
        let report = run(&pool, stranger).await.expect("verify");

        assert_eq!(report.vaults_checked, 0);
        assert_eq!(report.vaults_skipped, 1);
        assert_eq!(report.items_checked, 0);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].kind, "vault_key_unusable");

        let _ = std::fs::remove_dir_all(&root);
    }
}
