use chrono::Utc;
use std::io::Write;
use uuid::Uuid;
use zann_db::local::{
    HistorySource, HistorySyncStatus, KeyWrapType, LocalItem, LocalItemHistory,
    LocalItemHistoryRepo, LocalItemRepo, LocalPendingChange, LocalStorage, LocalVault,
    LocalVaultRepo,
};

use crate::crypto::{decrypt_payload, payload_aad, payload_checksum};
use crate::http::decode_json_response;
use crate::types::{
    SyncAppliedChange, SyncPullChange, SyncSharedPullChange, SyncSharedPushChange,
    VaultDetailResponse, VaultListResponse,
};
use crate::util::{parse_rfc3339, storage_name_from_url};
use zann_core::crypto::{encrypt_blob, SecretKey};
use zann_core::{ChangeType, StorageKind, SyncStatus, VaultEncryptionType, VaultKind};

/// How many confirmed history versions to keep per item, matching the server's
/// `ITEM_HISTORY_LIMIT`. Keeping more would be pointless — the server never
/// sends a longer tail — and keeping fewer would drop versions the UI offers.
const HISTORY_LIMIT: i64 = 5;

fn append_sync_log(message: &str) {
    let Some(home) = dirs::home_dir() else {
        return;
    };
    let logs_dir = home.join(".zann").join("logs");
    let _ = std::fs::create_dir_all(&logs_dir);
    let log_path = logs_dir.join("sync.log");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    else {
        return;
    };
    let _ = writeln!(file, "{} {}", Utc::now().to_rfc3339(), message);
}

fn redact_uuid(id: Uuid) -> String {
    let value = id.as_hyphenated().to_string();
    let prefix = value.get(0..8).unwrap_or(&value);
    let suffix = value.get(value.len().saturating_sub(4)..).unwrap_or("");
    if value.len() > 12 {
        format!("{prefix}...{suffix}")
    } else {
        value
    }
}

pub async fn fetch_vault_details(
    client: &reqwest::Client,
    headers: &reqwest::header::HeaderMap,
    addr: &str,
    vaults: &VaultListResponse,
) -> Result<Vec<VaultDetailResponse>, String> {
    let mut details = Vec::with_capacity(vaults.vaults.len());
    for vault in &vaults.vaults {
        let detail_url = format!("{}/v1/vaults/{}", addr.trim_end_matches('/'), vault.id);
        let detail_resp = client
            .get(detail_url)
            .headers(headers.clone())
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !detail_resp.status().is_success() {
            let status = detail_resp.status();
            let body = detail_resp.text().await.unwrap_or_default();
            return Err(format!("vault_get_failed: {status} {body}"));
        }
        let detail = decode_json_response::<VaultDetailResponse>(detail_resp).await?;
        details.push(detail);
    }
    Ok(details)
}

pub fn build_remote_storage(
    storage_uuid: Uuid,
    addr: &str,
    system_info: Option<&crate::types::SystemInfoResponse>,
    config: &crate::state::CliConfig,
) -> LocalStorage {
    LocalStorage {
        id: storage_uuid,
        kind: StorageKind::Remote,
        name: format!("Remote ({})", storage_name_from_url(addr)),
        server_url: Some(addr.to_string()),
        server_name: system_info.and_then(|info| info.server_name.clone()),
        server_fingerprint: system_info.map(|info| info.server_fingerprint.clone()),
        account_subject: config
            .identity
            .as_ref()
            .and_then(|identity| identity.email.clone()),
        personal_vaults_enabled: system_info
            .map(|info| info.personal_vaults_enabled)
            .unwrap_or(true),
        auth_method: None,
    }
}

pub async fn ensure_local_vaults(
    vault_repo: &LocalVaultRepo<'_>,
    storage_uuid: Uuid,
    vault_details: &[VaultDetailResponse],
) -> Result<(), String> {
    for vault in vault_details {
        let vault_id = Uuid::parse_str(&vault.id).map_err(|err| err.to_string())?;
        let exists = vault_repo
            .get_by_id(storage_uuid, vault_id)
            .await
            .map_err(|err| err.to_string())?;
        if exists.is_some() {
            continue;
        }
        let encryption_type = VaultEncryptionType::try_from(vault.encryption_type)
            .map_err(|_| "invalid vault encryption type".to_string())?;
        let key_wrap_type = if encryption_type == VaultEncryptionType::Server {
            KeyWrapType::RemoteServer
        } else {
            KeyWrapType::RemoteStrict
        };
        let kind = VaultKind::try_from(vault.kind).map_err(|_| "invalid vault kind".to_string())?;
        let record = LocalVault {
            id: vault_id,
            storage_id: storage_uuid,
            name: vault.name.clone(),
            kind,
            is_default: false,
            vault_key_enc: vault.vault_key_enc.clone(),
            key_wrap_type,
            last_synced_at: None,
        };
        let _ = vault_repo.create(&record).await;
    }
    Ok(())
}

pub async fn handle_sync_conflict(
    item_repo: &LocalItemRepo<'_>,
    storage_id: Uuid,
    vault_id: Uuid,
    change: &LocalPendingChange,
) -> Result<Option<Uuid>, String> {
    let payload_enc = match change.payload_enc.as_ref() {
        Some(payload) => payload.clone(),
        None => return Ok(None),
    };
    let checksum = change
        .checksum
        .clone()
        .unwrap_or_else(|| payload_checksum(&payload_enc));
    let path = change
        .path
        .clone()
        .unwrap_or_else(|| "conflict".to_string());
    let name = change.name.clone().unwrap_or_else(|| path.clone());
    let type_id = change
        .type_id
        .clone()
        .unwrap_or_else(|| "login".to_string());

    let now = Utc::now();
    let mut suffix = format!(" (conflict {})", now.format("%Y%m%d-%H%M%S"));
    let mut candidate = format!("{}{}", path, suffix);
    let mut attempts = 0;
    while item_repo
        .get_by_vault_path(storage_id, vault_id, &candidate)
        .await
        .map_err(|err| err.to_string())?
        .is_some()
    {
        attempts += 1;
        suffix = format!(" (conflict {}-{})", now.format("%Y%m%d-%H%M%S"), attempts);
        candidate = format!("{}{}", path, suffix);
        if attempts > 5 {
            break;
        }
    }

    if let Ok(Some(mut existing)) = item_repo.get_by_id(storage_id, change.item_id).await {
        existing.path = candidate.clone();
        existing.name = format!("{}{}", name, suffix);
        existing.type_id = type_id;
        existing.payload_enc = payload_enc;
        existing.checksum = checksum;
        existing.sync_status = SyncStatus::Conflict;
        existing.updated_at = now;
        item_repo
            .update(&existing)
            .await
            .map_err(|err| err.to_string())?;
        return Ok(Some(existing.id));
    }

    let conflict_item = LocalItem {
        id: Uuid::now_v7(),
        storage_id,
        vault_id,
        path: candidate.clone(),
        name: format!("{}{}", name, suffix),
        type_id,
        payload_enc,
        checksum,
        cache_key_fp: None,
        version: change.base_seq.unwrap_or(0) + 1,
        deleted_at: None,
        updated_at: now,
        sync_status: SyncStatus::Conflict,
    };
    item_repo
        .create(&conflict_item)
        .await
        .map_err(|err| err.to_string())?;
    Ok(Some(conflict_item.id))
}

pub fn build_shared_push_changes(
    pending: &[LocalPendingChange],
    master_key: &SecretKey,
    vault_id: Uuid,
) -> Result<Vec<SyncSharedPushChange>, String> {
    let mut changes = Vec::with_capacity(pending.len());
    for change in pending {
        if change.operation == ChangeType::Delete {
            changes.push(SyncSharedPushChange {
                item_id: change.item_id.to_string(),
                operation: change.operation.as_i32(),
                payload: None,
                path: change.path.clone(),
                name: change.name.clone(),
                type_id: change.type_id.clone(),
                base_seq: change.base_seq,
            });
            continue;
        }

        let payload_enc = change
            .payload_enc
            .as_ref()
            .ok_or_else(|| "missing payload".to_string())?;
        let payload = decrypt_payload(master_key, vault_id, change.item_id, payload_enc)?;
        let payload_json = serde_json::to_value(payload).map_err(|err| err.to_string())?;
        changes.push(SyncSharedPushChange {
            item_id: change.item_id.to_string(),
            operation: change.operation.as_i32(),
            payload: Some(payload_json),
            path: change.path.clone(),
            name: change.name.clone(),
            type_id: change.type_id.clone(),
            base_seq: change.base_seq,
        });
    }
    Ok(changes)
}

pub async fn apply_push_applied(
    item_repo: &LocalItemRepo<'_>,
    storage_id: Uuid,
    _vault_id: Uuid,
    changes: &[SyncAppliedChange],
) -> Result<(), String> {
    for change in changes {
        let item_id = Uuid::parse_str(&change.item_id).map_err(|err| err.to_string())?;
        let updated_at = match parse_rfc3339(&change.updated_at) {
            Some(value) => value,
            None => Utc::now(),
        };
        let deleted_at = match change.deleted_at.as_ref() {
            Some(value) => parse_rfc3339(value),
            None => None,
        };
        if let Ok(Some(mut existing)) = item_repo.get_by_id(storage_id, item_id).await {
            existing.updated_at = updated_at;
            existing.deleted_at = deleted_at;
            existing.version = change.seq;
            existing.sync_status = if deleted_at.is_some() {
                SyncStatus::Tombstone
            } else {
                SyncStatus::Synced
            };
            let _ = item_repo.update(&existing).await;
        }
    }
    Ok(())
}

pub async fn apply_pull_change(
    item_repo: &LocalItemRepo<'_>,
    history_repo: &LocalItemHistoryRepo<'_>,
    vault_key: &SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    change: &SyncPullChange,
) -> Result<bool, String> {
    let item_id = Uuid::parse_str(&change.item_id).map_err(|err| err.to_string())?;
    // A timestamp we cannot read must not be stamped "now": that would make the
    // change look newer than everything local and win the next comparison.
    let updated_at = match parse_rfc3339(&change.updated_at) {
        Some(value) => value,
        None => {
            append_sync_log(&format!(
                "[pull] invalid updated_at: storage_id={}, item_id={}, value={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                change.updated_at
            ));
            return Ok(false);
        }
    };

    let existing = item_repo
        .get_by_id(storage_id, item_id)
        .await
        .map_err(|err| err.to_string())?;
    // Strictly newer, not newer-or-equal: a correction re-issued at the same
    // seq has to be applied, and `>=` silently dropped it.
    if let Some(local) = existing.as_ref() {
        if local.version > change.seq {
            append_sync_log(&format!(
                "[pull] skipped newer local version: storage_id={}, item_id={}, local_version={}, remote_version={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                local.version,
                change.seq
            ));
            return Ok(false);
        }
    }

    // Deletion arrives as an operation. The server sends no `deleted_at` on a
    // pull change, so reading one meant deletions made on other devices never
    // landed here at all.
    if change.operation == ChangeType::Delete.as_i32() {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = SyncStatus::Tombstone;
            local.updated_at = updated_at;
            local.version = change.seq;
            item_repo
                .update(&local)
                .await
                .map_err(|err| err.to_string())?;
        }
        apply_pull_history(history_repo, storage_id, vault_id, item_id, change).await?;
        return Ok(true);
    }

    let payload_enc = match change.payload_enc.as_ref() {
        Some(payload) => payload.clone(),
        None => {
            append_sync_log(&format!(
                "[pull] missing payload_enc: storage_id={}, item_id={}",
                redact_uuid(storage_id),
                redact_uuid(item_id)
            ));
            return Ok(false);
        }
    };

    // Verify what arrived rather than describe it. Recomputing the checksum
    // from the received bytes makes any corruption self-consistent, which is
    // the same as not checking at all.
    let checksum = payload_checksum(&payload_enc);
    if checksum != change.checksum {
        append_sync_log(&format!(
            "[pull] checksum mismatch: storage_id={}, item_id={}",
            redact_uuid(storage_id),
            redact_uuid(item_id)
        ));
        return Ok(false);
    }

    let key_fp = key_fingerprint(vault_key);
    if decrypt_payload(vault_key, vault_id, item_id, &payload_enc).is_err() {
        append_sync_log(&format!(
            "[pull] decrypt failed: storage_id={}, item_id={}",
            redact_uuid(storage_id),
            redact_uuid(item_id)
        ));
        return Ok(false);
    }

    if let Some(mut local) = existing {
        local.path = change.path.clone();
        local.name = change.name.clone();
        local.type_id = change.type_id.clone();
        local.payload_enc = payload_enc;
        local.checksum = change.checksum.clone();
        // Which key this cache was written under, so a rotation can invalidate it.
        local.cache_key_fp = Some(key_fp);
        local.version = change.seq;
        local.updated_at = updated_at;
        local.deleted_at = None;
        local.sync_status = SyncStatus::Synced;
        item_repo
            .update(&local)
            .await
            .map_err(|err| err.to_string())?;
    } else {
        let record = LocalItem {
            id: item_id,
            storage_id,
            vault_id,
            path: change.path.clone(),
            name: change.name.clone(),
            type_id: change.type_id.clone(),
            payload_enc,
            checksum: change.checksum.clone(),
            cache_key_fp: Some(key_fp),
            version: change.seq,
            deleted_at: None,
            updated_at,
            sync_status: SyncStatus::Synced,
        };
        item_repo
            .create(&record)
            .await
            .map_err(|err| err.to_string())?;
    }

    apply_pull_history(history_repo, storage_id, vault_id, item_id, change).await?;

    Ok(true)
}

/// Server history rows for one item, mapped onto the local shape.
async fn apply_pull_history(
    history_repo: &LocalItemHistoryRepo<'_>,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    change: &SyncPullChange,
) -> Result<(), String> {
    let history_entries = change
        .history
        .iter()
        .map(|entry| LocalItemHistory {
            id: Uuid::now_v7(),
            storage_id,
            vault_id,
            item_id,
            payload_enc: entry.payload_enc.clone(),
            checksum: entry.checksum.clone(),
            version: entry.version,
            change_type: ChangeType::try_from(entry.change_type).unwrap_or(ChangeType::Update),
            changed_by_email: entry.changed_by_email.clone(),
            changed_by_name: entry.changed_by_name.clone(),
            changed_by_device_id: None,
            changed_by_device_name: None,
            source: HistorySource::Server,
            sync_status: HistorySyncStatus::Confirmed,
            created_at: parse_rfc3339(&entry.created_at).unwrap_or_else(Utc::now),
        })
        .collect::<Vec<_>>();

    apply_history_payloads(
        "history",
        history_repo,
        storage_id,
        item_id,
        &history_entries,
    )
    .await
}

/// The shared-vault counterpart of [`apply_pull_change`].
///
/// The server holds the key for these vaults and sends the payload as plaintext
/// JSON, so there is nothing to decrypt and nothing to check a checksum
/// against: the `checksum` on the wire describes the server's ciphertext, which
/// never reaches us. What we store is a local cache encrypted under the master
/// key, described by its own checksum.
pub async fn apply_shared_pull_change(
    item_repo: &LocalItemRepo<'_>,
    history_repo: &LocalItemHistoryRepo<'_>,
    master_key: &SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    change: &SyncSharedPullChange,
) -> Result<bool, String> {
    let item_id = Uuid::parse_str(&change.item_id).map_err(|err| err.to_string())?;
    // A timestamp we cannot read must not be stamped "now": that would make the
    // change look newer than everything local and win the next comparison.
    let updated_at = match parse_rfc3339(&change.updated_at) {
        Some(value) => value,
        None => {
            append_sync_log(&format!(
                "[pull_shared] invalid updated_at: storage_id={}, item_id={}, value={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                change.updated_at
            ));
            return Ok(false);
        }
    };

    let existing = item_repo
        .get_by_id(storage_id, item_id)
        .await
        .map_err(|err| err.to_string())?;
    // Strictly newer, not newer-or-equal. This matters more here than for a
    // personal vault: the server's bootstrap path stamps every item with the
    // vault's current seq, so `>=` dropped the whole vault on a second bootstrap.
    if let Some(local) = existing.as_ref() {
        if local.version > change.seq {
            append_sync_log(&format!(
                "[pull_shared] skipped newer local version: storage_id={}, item_id={}, local_version={}, remote_version={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                local.version,
                change.seq
            ));
            return Ok(false);
        }
    }

    // Deletion arrives as an operation. The shared pull response has no
    // `deleted_at` field at all, so reading one meant a deletion in a shared
    // vault never landed here.
    if change.operation == ChangeType::Delete.as_i32() {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = SyncStatus::Tombstone;
            local.updated_at = updated_at;
            local.version = change.seq;
            item_repo
                .update(&local)
                .await
                .map_err(|err| err.to_string())?;
        }
        apply_shared_pull_history(
            history_repo,
            master_key,
            storage_id,
            vault_id,
            item_id,
            change,
        )
        .await?;
        return Ok(true);
    }

    // An update carrying no payload is a malformed change, not an instruction
    // to blank the item.
    let Some(payload) = change.payload.as_ref() else {
        append_sync_log(&format!(
            "[pull_shared] missing payload: storage_id={}, item_id={}",
            redact_uuid(storage_id),
            redact_uuid(item_id)
        ));
        return Ok(false);
    };
    let (payload_enc, checksum) =
        encrypt_payload_for_cache(master_key, vault_id, item_id, payload)?;
    let key_fp = key_fingerprint(master_key);

    if let Some(mut local) = existing {
        local.path = change.path.clone();
        local.name = change.name.clone();
        local.type_id = change.type_id.clone();
        local.payload_enc = payload_enc;
        local.checksum = checksum;
        // Which key this cache was written under, so a rotation can invalidate it.
        local.cache_key_fp = Some(key_fp);
        local.version = change.seq;
        local.updated_at = updated_at;
        local.deleted_at = None;
        local.sync_status = SyncStatus::Synced;
        item_repo
            .update(&local)
            .await
            .map_err(|err| err.to_string())?;
    } else {
        let record = LocalItem {
            id: item_id,
            storage_id,
            vault_id,
            path: change.path.clone(),
            name: change.name.clone(),
            type_id: change.type_id.clone(),
            payload_enc,
            checksum,
            cache_key_fp: Some(key_fp),
            version: change.seq,
            deleted_at: None,
            updated_at,
            sync_status: SyncStatus::Synced,
        };
        item_repo
            .create(&record)
            .await
            .map_err(|err| err.to_string())?;
    }

    apply_shared_pull_history(
        history_repo,
        master_key,
        storage_id,
        vault_id,
        item_id,
        change,
    )
    .await?;

    Ok(true)
}

/// Server history rows for one shared item, re-encrypted for the local cache.
///
/// A row that cannot be encrypted fails the whole change rather than being
/// stored with no bytes: an empty entry reads as a version that exists and shows
/// nothing, which is worse than a sync error somebody can retry.
async fn apply_shared_pull_history(
    history_repo: &LocalItemHistoryRepo<'_>,
    master_key: &SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    change: &SyncSharedPullChange,
) -> Result<(), String> {
    let mut history_entries = Vec::with_capacity(change.history.len());
    for entry in &change.history {
        let (payload_enc, checksum) =
            encrypt_payload_for_cache(master_key, vault_id, item_id, &entry.payload)?;
        history_entries.push(LocalItemHistory {
            id: Uuid::now_v7(),
            storage_id,
            vault_id,
            item_id,
            payload_enc,
            // The server's checksum covers its own ciphertext; ours has to
            // describe the bytes actually cached, or `verify` reports every
            // shared item as corrupt.
            checksum,
            version: entry.version,
            change_type: ChangeType::try_from(entry.change_type).unwrap_or(ChangeType::Update),
            changed_by_email: entry.changed_by_email.clone(),
            changed_by_name: entry.changed_by_name.clone(),
            changed_by_device_id: None,
            changed_by_device_name: None,
            source: HistorySource::Server,
            sync_status: HistorySyncStatus::Confirmed,
            created_at: parse_rfc3339(&entry.created_at).unwrap_or_else(Utc::now),
        });
    }

    apply_history_payloads(
        "shared_history",
        history_repo,
        storage_id,
        item_id,
        &history_entries,
    )
    .await
}

/// Fold the server's history tail into what is already stored.
///
/// A merge, not a replace. `replace_by_item` deletes every row for the item
/// before writing the tail, which destroys two things the server cannot give
/// back: a *pending* row for a local edit that has not been pushed yet — the
/// only copy of that version anywhere — and, when a change arrives with no
/// history at all, the entire stored history of the item.
///
/// `tag` only distinguishes the two vault kinds in the log.
async fn apply_history_payloads(
    tag: &str,
    history_repo: &LocalItemHistoryRepo<'_>,
    storage_id: Uuid,
    item_id: Uuid,
    history: &[LocalItemHistory],
) -> Result<(), String> {
    if history.is_empty() {
        append_sync_log(&format!(
            "[{tag}] empty history: storage_id={}, item_id={}",
            redact_uuid(storage_id),
            redact_uuid(item_id)
        ));
        return Ok(());
    }
    match history_repo
        .merge_by_item(storage_id, item_id, history, HISTORY_LIMIT)
        .await
    {
        Ok(()) => {
            append_sync_log(&format!(
                "[{tag}] applied: storage_id={}, item_id={}, entries={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                history.len()
            ));
            Ok(())
        }
        Err(err) => {
            append_sync_log(&format!(
                "[{tag}] apply failed: storage_id={}, item_id={}, error={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                err
            ));
            Err(err.to_string())
        }
    }
}

pub fn encrypt_payload_for_cache(
    master_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload: &serde_json::Value,
) -> Result<(Vec<u8>, String), String> {
    let payload_bytes = serde_json::to_vec(payload).map_err(|err| err.to_string())?;
    let aad = payload_aad(vault_id, item_id);
    let blob = encrypt_blob(master_key, &payload_bytes, &aad).map_err(|err| err.to_string())?;
    let payload_enc = blob.to_bytes();
    let checksum = payload_checksum(&payload_enc);
    Ok((payload_enc, checksum))
}

pub fn key_fingerprint(key: &SecretKey) -> String {
    let hex = blake3::hash(key.as_bytes()).to_hex().to_string();
    hex.get(0..12).unwrap_or(&hex).to_string()
}
