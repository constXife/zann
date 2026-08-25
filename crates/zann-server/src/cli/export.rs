use chrono::Utc;
use clap::Args;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zann_core::{Item, Vault, VaultEncryptionType, VaultKind};
use zann_crypto::secrets::EncryptedPayload;
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{ItemRepo, VaultRepo};
use zann_db::PgPool;
use zeroize::Zeroizing;

use crate::settings;

const EXPORT_VERSION: u32 = 1;
const MAX_ALL_SHARED_EXPORT_VAULTS: usize = 64;
const ALL_SHARED_EXPORT_LOOKAHEAD: i64 = 65;
const MAX_SHARED_EXPORT_ITEMS: usize = 120;
const MAX_SHARED_EXPORT_SOURCE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default)]
struct ExportBudget {
    items: usize,
    source_bytes: usize,
}

impl ExportBudget {
    fn reserve(&mut self, items: i64, source_bytes: i64) -> Result<usize, String> {
        let items = usize::try_from(items).map_err(|_| "export_budget_invalid".to_string())?;
        let source_bytes =
            usize::try_from(source_bytes).map_err(|_| "export_budget_invalid".to_string())?;
        let next_items = self
            .items
            .checked_add(items)
            .ok_or_else(|| "export_item_limit_exceeded".to_string())?;
        if next_items > MAX_SHARED_EXPORT_ITEMS {
            return Err("export_item_limit_exceeded".to_string());
        }
        let next_source_bytes = self
            .source_bytes
            .checked_add(source_bytes)
            .ok_or_else(|| "export_size_limit_exceeded".to_string())?;
        if next_source_bytes > MAX_SHARED_EXPORT_SOURCE_BYTES {
            return Err("export_size_limit_exceeded".to_string());
        }
        self.items = next_items;
        self.source_bytes = next_source_bytes;
        Ok(items)
    }
}

#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    #[arg(
        long,
        value_name = "slug-or-id",
        conflicts_with = "all_shared",
        help = "Shared vault slug or UUID to export; repeat to export multiple vaults"
    )]
    pub vault: Vec<String>,
    #[arg(
        long,
        conflicts_with = "vault",
        help = "Export all shared server-encrypted vaults"
    )]
    pub all_shared: bool,
    #[arg(long, help = "Include deleted items in the export")]
    pub include_deleted: bool,
    #[arg(
        long,
        value_name = "path",
        help = "Write the plaintext export to a file instead of stdout"
    )]
    pub out: Option<PathBuf>,
    #[arg(
        long,
        help = "Required confirmation for plaintext export of shared secrets"
    )]
    pub i_understand_plaintext: bool,
}

#[derive(Debug, Serialize)]
struct SharedExportOutput {
    version: u32,
    exported_at: String,
    scope: &'static str,
    plaintext: bool,
    vaults: Vec<SharedExportVault>,
}

#[derive(Debug, Serialize)]
struct SharedExportVault {
    id: String,
    slug: String,
    name: String,
    item_count: usize,
    items: Vec<SharedExportItem>,
}

#[derive(Debug, Serialize)]
struct SharedExportItem {
    id: String,
    path: String,
    name: String,
    type_id: String,
    tags: Option<Vec<String>>,
    favorite: bool,
    payload: EncryptedPayload,
    checksum: String,
    version: i64,
    deleted_at: Option<String>,
    updated_at: String,
}

pub(crate) async fn run(
    settings: &settings::Settings,
    db: &PgPool,
    args: &ExportArgs,
) -> Result<(), String> {
    if !args.i_understand_plaintext {
        return Err("plaintext_confirmation_required".to_string());
    }
    validate_selection(args)?;

    let vaults = resolve_vaults(db, args).await?;
    if vaults.is_empty() {
        return Err("no_shared_vaults_found".to_string());
    }

    let item_repo = ItemRepo::new(db);
    let mut tx = db
        .begin()
        .await
        .map_err(db_error("export_snapshot_begin_failed"))?;
    sqlx_core::query::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(db_error("export_snapshot_config_failed"))?;

    // Prove the full aggregate allocation budget before fetching or decrypting
    // even the first payload. The later bounded reads use this same snapshot.
    let mut budget = ExportBudget::default();
    let mut vault_budgets = Vec::with_capacity(vaults.len());
    for vault in vaults {
        let (item_count, source_bytes) = item_repo
            .export_budget_by_vault_in(&mut tx, vault.id, args.include_deleted)
            .await
            .map_err(db_error("export_budget_lookup_failed"))?;
        let item_count = budget.reserve(item_count, source_bytes)?;
        vault_budgets.push((vault, item_count));
    }

    let mut export_vaults = Vec::with_capacity(vault_budgets.len());
    for (vault, expected_item_count) in vault_budgets {
        let lookahead = expected_item_count
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| "export_item_limit_exceeded".to_string())?;
        let mut items = item_repo
            .list_by_vault_bounded_in(&mut tx, vault.id, args.include_deleted, lookahead)
            .await
            .map_err(db_error("export_items_lookup_failed"))?;
        if items.len() != expected_item_count {
            return Err("export_snapshot_inconsistent".to_string());
        }
        items.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.updated_at.cmp(&right.updated_at))
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut export_items = Vec::with_capacity(items.len());
        for item in items {
            let payload = decrypt_payload(settings, &vault, &item)?;
            export_items.push(SharedExportItem {
                id: item.id.to_string(),
                path: item.path,
                name: item.name,
                type_id: item.type_id,
                tags: item.tags.map(|tags| tags.0),
                favorite: item.favorite,
                payload,
                checksum: item.checksum,
                version: item.version,
                deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
                updated_at: item.updated_at.to_rfc3339(),
            });
        }

        export_vaults.push(SharedExportVault {
            id: vault.id.to_string(),
            slug: vault.slug,
            name: vault.name,
            item_count: export_items.len(),
            items: export_items,
        });
    }
    tx.commit()
        .await
        .map_err(db_error("export_snapshot_commit_failed"))?;

    let output = SharedExportOutput {
        version: EXPORT_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        scope: "shared",
        plaintext: true,
        vaults: export_vaults,
    };
    let json = Zeroizing::new(
        serde_json::to_string_pretty(&output)
            .map_err(|err| format!("export_encode_failed: {err}"))?,
    );

    match args.out.as_deref() {
        Some(path) => write_private_json_file(path, &json),
        None => {
            println!("{}", json.as_str());
            Ok(())
        }
    }
}

fn validate_selection(args: &ExportArgs) -> Result<(), String> {
    if args.all_shared {
        return Ok(());
    }
    if args.vault.is_empty() {
        return Err("export_scope_required".to_string());
    }
    Ok(())
}

async fn resolve_vaults(db: &PgPool, args: &ExportArgs) -> Result<Vec<Vault>, String> {
    let repo = VaultRepo::new(db);
    let mut selected = Vec::new();
    let mut seen = HashSet::new();

    if args.all_shared {
        let mut vaults = repo
            .list_shared_server_bounded(ALL_SHARED_EXPORT_LOOKAHEAD)
            .await
            .map_err(db_error("export_vault_lookup_failed"))?;
        if vaults.len() > MAX_ALL_SHARED_EXPORT_VAULTS {
            return Err("export_vault_limit_exceeded".to_string());
        }
        vaults.sort_by(|left, right| {
            left.slug
                .cmp(&right.slug)
                .then_with(|| left.id.cmp(&right.id))
        });
        return Ok(vaults);
    }

    for selector in &args.vault {
        let selector = selector.trim();
        if selector.is_empty() {
            return Err("invalid_vault_selector".to_string());
        }

        let vault = if let Ok(vault_id) = selector.parse::<Uuid>() {
            repo.get_by_id(vault_id)
                .await
                .map_err(db_error("export_vault_lookup_failed"))?
        } else {
            repo.get_by_slug(selector)
                .await
                .map_err(db_error("export_vault_lookup_failed"))?
        }
        .ok_or_else(|| "vault_not_found".to_string())?;

        ensure_shared_server_vault(&vault)?;
        if seen.insert(vault.id) {
            selected.push(vault);
        }
    }

    selected.sort_by(|left, right| {
        left.slug
            .cmp(&right.slug)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(selected)
}

fn is_shared_server_vault(vault: &Vault) -> bool {
    vault.kind == VaultKind::Shared && vault.encryption_type == VaultEncryptionType::Server
}

fn ensure_shared_server_vault(vault: &Vault) -> Result<(), String> {
    if !is_shared_server_vault(vault) {
        return Err("vault_not_shared_server_encrypted".to_string());
    }
    Ok(())
}

fn decrypt_payload(
    settings: &settings::Settings,
    vault: &Vault,
    item: &Item,
) -> Result<EncryptedPayload, String> {
    let smk = settings
        .server_master_key
        .as_ref()
        .ok_or_else(|| "server_master_key_missing".to_string())?;
    let vault_key = core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc)
        .map_err(|err| format!("vault_key_decrypt_failed: {err}"))?;
    let payload_bytes = Zeroizing::new(
        core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item.id, &item.payload_enc)
            .map_err(|err| format!("payload_decrypt_failed: {err}"))?,
    );
    EncryptedPayload::from_bytes(&payload_bytes)
        .map_err(|err| format!("payload_decode_failed: {err}"))
}

fn write_private_json_file(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|err| format!("export_create_dir_failed: {err}"))?;

    let tmp_path = parent.join(format!(".{}.tmp", Uuid::now_v7()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|err| format!("export_open_failed: {err}"))?;
    file.write_all(contents.as_bytes())
        .map_err(|err| format!("export_write_failed: {err}"))?;
    file.write_all(b"\n")
        .map_err(|err| format!("export_write_failed: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("export_sync_failed: {err}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("export_chmod_failed: {err}"))?;
    fs::rename(&tmp_path, path).map_err(|err| format!("export_rename_failed: {err}"))?;
    Ok(())
}

fn db_error(label: &'static str) -> impl Fn(sqlx_core::Error) -> String {
    move |err| {
        tracing::error!(event = label, error = %err);
        label.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_selection_requires_scope_without_all_shared() {
        let args = ExportArgs {
            vault: Vec::new(),
            all_shared: false,
            include_deleted: false,
            out: None,
            i_understand_plaintext: true,
        };
        assert_eq!(
            validate_selection(&args).expect_err("selection should fail"),
            "export_scope_required"
        );
    }

    #[test]
    fn validate_selection_all_shared_is_allowed() {
        let args = ExportArgs {
            vault: Vec::new(),
            all_shared: true,
            include_deleted: false,
            out: None,
            i_understand_plaintext: true,
        };
        validate_selection(&args).expect("all_shared should be valid");
    }

    #[test]
    fn export_budget_accepts_exact_boundaries() {
        let mut budget = ExportBudget::default();
        assert_eq!(
            budget
                .reserve(
                    MAX_SHARED_EXPORT_ITEMS as i64,
                    MAX_SHARED_EXPORT_SOURCE_BYTES as i64,
                )
                .expect("exact boundary"),
            MAX_SHARED_EXPORT_ITEMS
        );
    }

    #[test]
    fn export_budget_rejects_item_and_size_lookahead() {
        let mut item_budget = ExportBudget::default();
        assert_eq!(
            item_budget
                .reserve(MAX_SHARED_EXPORT_ITEMS as i64 + 1, 0)
                .expect_err("item lookahead must fail"),
            "export_item_limit_exceeded"
        );

        let mut size_budget = ExportBudget::default();
        assert_eq!(
            size_budget
                .reserve(1, MAX_SHARED_EXPORT_SOURCE_BYTES as i64 + 1)
                .expect_err("size lookahead must fail"),
            "export_size_limit_exceeded"
        );
    }
}
