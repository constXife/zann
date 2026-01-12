use chrono::Utc;
use std::io::Write;
use uuid::Uuid;
use zann_db::local::{
    KeyWrapType, LocalItem, LocalItemHistory, LocalItemHistoryRepo, LocalItemRepo,
    LocalPendingChange, LocalStorage, LocalVault, LocalVaultRepo,
};

use crate::crypto::{decrypt_payload, payload_aad, payload_checksum};
use crate::infra::http::decode_json_response;
use crate::types::{
    SyncAppliedChange, SyncPullChange, SyncSharedPullChange, SyncSharedPushChange,
    VaultDetailResponse, VaultListResponse,
};
use crate::util::{parse_rfc3339, storage_name_from_url};
use zann_core::crypto::{encrypt_blob, SecretKey};
use zann_core::{ChangeType, StorageKind, SyncStatus, VaultEncryptionType, VaultKind};

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

pub(crate) async fn fetch_vault_details(
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

pub(crate) fn build_remote_storage(
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

pub(crate) async fn ensure_local_vaults(
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
        let kind = VaultKind::try_from(vault.kind)
            .map_err(|_| "invalid vault kind".to_string())?;
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

pub(crate) async fn handle_sync_conflict(
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
    let path = change.path.clone().unwrap_or_else(|| "conflict".to_string());
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
        item_repo.update(&existing).await.map_err(|err| err.to_string())?;
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

pub(crate) fn build_shared_push_changes(
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

pub(crate) async fn apply_push_applied(
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
        let Some(mut local) = item_repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| err.to_string())?
        else {
            continue;
        };
        local.version = change.seq;
        local.updated_at = updated_at;
        local.deleted_at = deleted_at;
        local.sync_status = if deleted_at.is_some() {
            SyncStatus::Tombstone
        } else {
            SyncStatus::Synced
        };
        item_repo.update(&local).await.map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub(crate) async fn apply_pull_change(
    item_repo: &LocalItemRepo<'_>,
    history_repo: &LocalItemHistoryRepo<'_>,
    vault_key: &zann_core::crypto::SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    change: &SyncPullChange,
) -> Result<bool, String> {
    let item_id = Uuid::parse_str(&change.item_id).map_err(|err| err.to_string())?;
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
    if change.operation == ChangeType::Delete.as_i32() {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = SyncStatus::Tombstone;
            local.updated_at = updated_at;
            local.version = change.seq;
            item_repo.update(&local).await.map_err(|err| err.to_string())?;
        }
        apply_history_payloads(history_repo, storage_id, vault_id, item_id, &change.history)
            .await?;
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
        local.cache_key_fp = Some(key_fp);
        local.updated_at = updated_at;
        local.deleted_at = None;
        local.sync_status = SyncStatus::Synced;
        local.version = change.seq;
        item_repo.update(&local).await.map_err(|err| err.to_string())?;
        apply_history_payloads(history_repo, storage_id, vault_id, item_id, &change.history)
            .await?;
        return Ok(true);
    }

    let item = LocalItem {
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
    item_repo.create(&item).await.map_err(|err| err.to_string())?;
    apply_history_payloads(history_repo, storage_id, vault_id, item_id, &change.history).await?;
    Ok(true)
}

pub(crate) async fn apply_shared_pull_change(
    item_repo: &LocalItemRepo<'_>,
    history_repo: &LocalItemHistoryRepo<'_>,
    master_key: &SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    change: &SyncSharedPullChange,
) -> Result<bool, String> {
    let item_id = Uuid::parse_str(&change.item_id).map_err(|err| err.to_string())?;
    let updated_at = match parse_rfc3339(&change.updated_at) {
        Some(value) => value,
        None => return Ok(false),
    };

    let existing = item_repo
        .get_by_id(storage_id, item_id)
        .await
        .map_err(|err| err.to_string())?;
    if let Some(local) = existing.as_ref() {
        if local.version > change.seq {
            return Ok(false);
        }
    }
    if change.operation == ChangeType::Delete.as_i32() {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = SyncStatus::Tombstone;
            local.updated_at = updated_at;
            local.version = change.seq;
            item_repo.update(&local).await.map_err(|err| err.to_string())?;
        }
        apply_shared_history_payloads(
            history_repo,
            master_key,
            storage_id,
            vault_id,
            item_id,
            &change.history,
        )
        .await?;
        return Ok(true);
    }

    let Some(payload) = change.payload.as_ref() else {
        return Ok(false);
    };
    let (payload_enc, checksum) = encrypt_payload_for_cache(master_key, vault_id, item_id, payload)?;
    let key_fp = key_fingerprint(master_key);

    if let Some(mut local) = existing {
        local.path = change.path.clone();
        local.name = change.name.clone();
        local.type_id = change.type_id.clone();
        local.payload_enc = payload_enc;
        local.checksum = checksum;
        local.cache_key_fp = Some(key_fp);
        local.updated_at = updated_at;
        local.deleted_at = None;
        local.sync_status = SyncStatus::Synced;
        local.version = change.seq;
        item_repo.update(&local).await.map_err(|err| err.to_string())?;
        apply_shared_history_payloads(
            history_repo,
            master_key,
            storage_id,
            vault_id,
            item_id,
            &change.history,
        )
        .await?;
        return Ok(true);
    }

    let item = LocalItem {
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
        .create(&item)
        .await
        .map_err(|err| err.to_string())?;
    apply_shared_history_payloads(
        history_repo,
        master_key,
        storage_id,
        vault_id,
        item_id,
        &change.history,
    )
    .await?;
    Ok(true)
}

async fn apply_history_payloads(
    history_repo: &LocalItemHistoryRepo<'_>,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    history: &[crate::types::SyncHistoryEntry],
) -> Result<(), String> {
    if history.is_empty() {
        append_sync_log(&format!(
            "[history] empty history: storage_id={}, item_id={}",
            redact_uuid(storage_id),
            redact_uuid(item_id)
        ));
        return Ok(());
    }
    let mut entries = Vec::with_capacity(history.len());
    for entry in history {
        let change_type = ChangeType::try_from(entry.change_type)
            .map_err(|_| "invalid change type".to_string())?;
        entries.push(LocalItemHistory {
            id: Uuid::now_v7(),
            storage_id,
            vault_id,
            item_id,
            payload_enc: entry.payload_enc.clone(),
            checksum: entry.checksum.clone(),
            version: entry.version,
            change_type,
            changed_by_email: entry.changed_by_email.clone(),
            changed_by_name: entry.changed_by_name.clone(),
            changed_by_device_id: None,
            changed_by_device_name: None,
            created_at: parse_rfc3339(&entry.created_at).unwrap_or_else(Utc::now),
        });
    }
    match history_repo
        .replace_by_item(storage_id, item_id, &entries)
        .await
    {
        Ok(()) => {
            append_sync_log(&format!(
                "[history] applied: storage_id={}, item_id={}, entries={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                entries.len()
            ));
            eprintln!(
                "[sync] applied history: storage_id={}, item_id={}, entries={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                entries.len()
            );
            Ok(())
        }
        Err(err) => {
            append_sync_log(&format!(
                "[history] apply failed: storage_id={}, item_id={}, error={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                err
            ));
            eprintln!(
                "[sync] history apply failed: storage_id={}, item_id={}, error={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                err
            );
            Err(err.to_string())
        }
    }
}

async fn apply_shared_history_payloads(
    history_repo: &LocalItemHistoryRepo<'_>,
    master_key: &SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    item_id: Uuid,
    history: &[crate::types::SyncSharedHistoryEntry],
) -> Result<(), String> {
    if history.is_empty() {
        append_sync_log(&format!(
            "[shared_history] empty history: storage_id={}, item_id={}",
            redact_uuid(storage_id),
            redact_uuid(item_id)
        ));
        return Ok(());
    }
    let mut entries = Vec::with_capacity(history.len());
    for entry in history {
        let (payload_enc, checksum) =
            encrypt_payload_for_cache(master_key, vault_id, item_id, &entry.payload)?;
        let change_type = ChangeType::try_from(entry.change_type)
            .map_err(|_| "invalid change type".to_string())?;
        entries.push(LocalItemHistory {
            id: Uuid::now_v7(),
            storage_id,
            vault_id,
            item_id,
            payload_enc,
            checksum,
            version: entry.version,
            change_type,
            changed_by_email: entry.changed_by_email.clone(),
            changed_by_name: entry.changed_by_name.clone(),
            changed_by_device_id: None,
            changed_by_device_name: None,
            created_at: parse_rfc3339(&entry.created_at).unwrap_or_else(Utc::now),
        });
    }
    match history_repo
        .replace_by_item(storage_id, item_id, &entries)
        .await
    {
        Ok(()) => {
            append_sync_log(&format!(
                "[shared_history] applied: storage_id={}, item_id={}, entries={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                entries.len()
            ));
            eprintln!(
                "[sync] applied shared history: storage_id={}, item_id={}, entries={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                entries.len()
            );
            Ok(())
        }
        Err(err) => {
            append_sync_log(&format!(
                "[shared_history] apply failed: storage_id={}, item_id={}, error={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                err
            ));
            eprintln!(
                "[sync] shared history apply failed: storage_id={}, item_id={}, error={}",
                redact_uuid(storage_id),
                redact_uuid(item_id),
                err
            );
            Err(err.to_string())
        }
    }
}

pub(crate) fn encrypt_payload_for_cache(
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

pub(crate) fn key_fingerprint(key: &SecretKey) -> String {
    let hex = blake3::hash(key.as_bytes()).to_hex().to_string();
    hex.get(0..12).unwrap_or(&hex).to_string()
}
