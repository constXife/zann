use chrono::Utc;
use uuid::Uuid;
use zann_db::local::{
    LocalItem, LocalItemRepo, LocalPendingChange, LocalStorage, LocalVault, LocalVaultRepo,
};

use crate::crypto::{decrypt_payload, payload_aad, payload_checksum};
use crate::infra::http::decode_json_response;
use crate::types::{
    SyncAppliedChange, SyncPullChange, SyncSharedPullChange, SyncSharedPushChange,
    VaultDetailResponse, VaultListResponse,
};
use crate::util::{parse_rfc3339, storage_name_from_url};
use zann_core::crypto::{encrypt_blob, SecretKey};

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
        kind: "remote".to_string(),
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
        let key_wrap_type = if vault.encryption_type == "server" {
            "remote_server"
        } else {
            "remote_strict"
        };
        let record = LocalVault {
            id: vault_id,
            storage_id: storage_uuid,
            name: vault.name.clone(),
            kind: vault.kind.clone(),
            is_default: false,
            vault_key_enc: vault.vault_key_enc.clone(),
            key_wrap_type: key_wrap_type.to_string(),
            last_synced_at: None,
            server_seq: 0,
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
        existing.sync_status = "conflict".to_string();
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
        sync_status: "conflict".to_string(),
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
        if change.operation == "delete" {
            changes.push(SyncSharedPushChange {
                item_id: change.item_id.to_string(),
                operation: change.operation.clone(),
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
            operation: change.operation.clone(),
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
            "tombstone".to_string()
        } else {
            "synced".to_string()
        };
        item_repo.update(&local).await.map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub(crate) async fn apply_pull_change(
    item_repo: &LocalItemRepo<'_>,
    vault_key: &zann_core::crypto::SecretKey,
    storage_id: Uuid,
    vault_id: Uuid,
    change: &SyncPullChange,
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
        if local.updated_at > updated_at {
            return Ok(false);
        }
    }
    let operation = change.operation.as_str();

    if operation == "delete" {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = "tombstone".to_string();
            local.updated_at = updated_at;
            local.version = change.seq;
            item_repo.update(&local).await.map_err(|err| err.to_string())?;
        }
        return Ok(true);
    }

    let payload_enc = match change.payload_enc.as_ref() {
        Some(payload) => payload.clone(),
        None => return Ok(false),
    };
    let checksum = payload_checksum(&payload_enc);
    if checksum != change.checksum {
        return Ok(false);
    }
    let key_fp = key_fingerprint(vault_key);
    if decrypt_payload(vault_key, vault_id, item_id, &payload_enc).is_err() {
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
        local.sync_status = "synced".to_string();
        local.version = change.seq;
        item_repo.update(&local).await.map_err(|err| err.to_string())?;
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
        sync_status: "synced".to_string(),
    };
    item_repo.create(&item).await.map_err(|err| err.to_string())?;
    Ok(true)
}

pub(crate) async fn apply_shared_pull_change(
    item_repo: &LocalItemRepo<'_>,
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
        if local.updated_at > updated_at {
            return Ok(false);
        }
    }
    let operation = change.operation.as_str();

    if operation == "delete" {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = "tombstone".to_string();
            local.updated_at = updated_at;
            local.version = change.seq;
            item_repo.update(&local).await.map_err(|err| err.to_string())?;
        }
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
        local.sync_status = "synced".to_string();
        local.version = change.seq;
        item_repo.update(&local).await.map_err(|err| err.to_string())?;
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
        sync_status: "synced".to_string(),
    };
    item_repo
        .create(&item)
        .await
        .map_err(|err| err.to_string())?;
    Ok(true)
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
