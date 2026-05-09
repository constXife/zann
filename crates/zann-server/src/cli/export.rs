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

use crate::settings;

const EXPORT_VERSION: u32 = 1;

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
    let mut export_vaults = Vec::with_capacity(vaults.len());
    for vault in vaults {
        let mut items = item_repo
            .list_by_vault(vault.id, args.include_deleted)
            .await
            .map_err(db_error("export_items_lookup_failed"))?;
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

    let output = SharedExportOutput {
        version: EXPORT_VERSION,
        exported_at: Utc::now().to_rfc3339(),
        scope: "shared",
        plaintext: true,
        vaults: export_vaults,
    };
    let json = serde_json::to_string_pretty(&output)
        .map_err(|err| format!("export_encode_failed: {err}"))?;

    match args.out.as_deref() {
        Some(path) => write_private_json_file(path, &json),
        None => {
            println!("{json}");
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
            .list_all()
            .await
            .map_err(db_error("export_vault_lookup_failed"))?;
        vaults.retain(is_shared_server_vault);
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
    let payload_bytes =
        core_crypto::decrypt_payload_bytes(&vault_key, vault.id, item.id, &item.payload_enc)
            .map_err(|err| format!("payload_decrypt_failed: {err}"))?;
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
}
