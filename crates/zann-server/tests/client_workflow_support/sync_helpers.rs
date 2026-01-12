#![allow(dead_code)]

use chrono::{DateTime, Utc};
use serde_json::json;
use uuid::Uuid;
use zann_core::{ChangeType, SyncStatus};
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_db::local::{LocalItem, LocalItemRepo, LocalPendingChange, LocalVaultRepo};
use zann_db::SqlitePool;

use super::crypto::key_fingerprint;

pub(super) fn payload_checksum(payload_enc: &[u8]) -> String {
    core_crypto::payload_checksum(payload_enc)
}

fn decrypt_local_vault_key(
    master_key: &SecretKey,
    vault_id: Uuid,
    vault_key_enc: &[u8],
) -> SecretKey {
    core_crypto::decrypt_vault_key(master_key, vault_id, vault_key_enc).expect("decrypt vault key")
}

fn encrypt_payload_for_cache(
    master_key: &SecretKey,
    vault_id: Uuid,
    item_id: Uuid,
    payload: &serde_json::Value,
) -> (Vec<u8>, String) {
    let payload_bytes = serde_json::to_vec(payload).expect("payload encode");
    let payload_enc =
        core_crypto::encrypt_payload_bytes(master_key, vault_id, item_id, &payload_bytes)
            .expect("encrypt payload");
    let checksum = payload_checksum(&payload_enc);
    (payload_enc, checksum)
}

pub(super) async fn apply_shared_pull_change(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    master_key: &SecretKey,
    change: serde_json::Value,
) {
    let item_id = change["item_id"].as_str().unwrap();
    let item_id = Uuid::parse_str(item_id).expect("item id");
    let updated_at = change["updated_at"].as_str().unwrap();
    let updated_at = DateTime::parse_from_rfc3339(updated_at)
        .expect("updated_at")
        .with_timezone(&Utc);
    let operation = change["operation"].as_i64().unwrap_or(0) as i32;
    let operation = ChangeType::try_from(operation).ok();
    let repo = LocalItemRepo::new(pool);
    let existing = repo.get_by_id(storage_id, item_id).await.expect("get");

    if operation == Some(ChangeType::Delete) {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = SyncStatus::Tombstone;
            local.updated_at = updated_at;
            local.version = change["seq"].as_i64().unwrap_or(0);
            let _ = repo.update(&local).await;
        }
        return;
    }

    let payload = change
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let (payload_enc, checksum) =
        encrypt_payload_for_cache(master_key, vault_id, item_id, &payload);

    let path = change["path"].as_str().unwrap_or("").to_string();
    let name = change["name"].as_str().unwrap_or("").to_string();
    let type_id = change["type_id"].as_str().unwrap_or("").to_string();
    let version = change["seq"].as_i64().unwrap_or(0);
    let key_fp = blake3::hash(master_key.as_bytes()).to_hex().to_string();

    if let Some(mut local) = existing {
        local.path = path;
        local.name = name;
        local.type_id = type_id;
        local.payload_enc = payload_enc;
        local.checksum = checksum;
        local.cache_key_fp = Some(key_fp.get(0..12).unwrap_or(&key_fp).to_string());
        local.updated_at = updated_at;
        local.deleted_at = None;
        local.sync_status = SyncStatus::Synced;
        local.version = version;
        let _ = repo.update(&local).await;
        return;
    }

    let item = LocalItem {
        id: item_id,
        storage_id,
        vault_id,
        path,
        name,
        type_id,
        payload_enc,
        checksum,
        cache_key_fp: Some(key_fp.get(0..12).unwrap_or(&key_fp).to_string()),
        version,
        deleted_at: None,
        updated_at,
        sync_status: SyncStatus::Synced,
    };
    let _ = repo.create(&item).await;
}

pub(super) async fn apply_personal_pull_change(
    pool: &SqlitePool,
    storage_id: Uuid,
    vault_id: Uuid,
    master_key: &SecretKey,
    change: serde_json::Value,
) {
    let item_id = change["item_id"].as_str().unwrap();
    let item_id = Uuid::parse_str(item_id).expect("item id");
    let updated_at = change["updated_at"].as_str().unwrap();
    let updated_at = DateTime::parse_from_rfc3339(updated_at)
        .expect("updated_at")
        .with_timezone(&Utc);
    let operation = change["operation"].as_i64().unwrap_or(0) as i32;
    let operation = ChangeType::try_from(operation).ok();
    let repo = LocalItemRepo::new(pool);
    let existing = repo.get_by_id(storage_id, item_id).await.expect("get");

    if operation == Some(ChangeType::Delete) {
        if let Some(mut local) = existing {
            local.deleted_at = Some(updated_at);
            local.sync_status = SyncStatus::Tombstone;
            local.updated_at = updated_at;
            local.version = change["seq"].as_i64().unwrap_or(0);
            let _ = repo.update(&local).await;
        }
        return;
    }

    let payload_enc = change
        .get("payload_enc")
        .and_then(|value| value.as_array())
        .map(|bytes| {
            bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|v| v as u8))
                .collect::<Vec<u8>>()
        })
        .unwrap_or_default();
    let checksum = change["checksum"]
        .as_str()
        .map(|value| value.to_string())
        .unwrap_or_else(|| payload_checksum(&payload_enc));

    let path = change["path"].as_str().unwrap_or("").to_string();
    let name = change["name"].as_str().unwrap_or("").to_string();
    let type_id = change["type_id"].as_str().unwrap_or("").to_string();
    let version = change["seq"].as_i64().unwrap_or(0);
    let vault_repo = LocalVaultRepo::new(pool);
    let vault = vault_repo
        .get_by_id(storage_id, vault_id)
        .await
        .expect("vault")
        .expect("vault");
    let vault_key = decrypt_local_vault_key(master_key, vault_id, &vault.vault_key_enc);
    let key_fp = key_fingerprint(&vault_key);

    if let Some(mut local) = existing {
        local.path = path;
        local.name = name;
        local.type_id = type_id;
        local.payload_enc = payload_enc;
        local.checksum = checksum;
        local.cache_key_fp = Some(key_fp);
        local.updated_at = updated_at;
        local.deleted_at = None;
        local.sync_status = SyncStatus::Synced;
        local.version = version;
        let _ = repo.update(&local).await;
        return;
    }

    let item = LocalItem {
        id: item_id,
        storage_id,
        vault_id,
        path,
        name,
        type_id,
        payload_enc,
        checksum,
        cache_key_fp: Some(key_fp),
        version,
        deleted_at: None,
        updated_at,
        sync_status: SyncStatus::Synced,
    };
    let _ = repo.create(&item).await;
}

pub(super) async fn build_shared_push_changes(
    master_key: &SecretKey,
    vault_id: Uuid,
    pending: &[LocalPendingChange],
) -> Vec<serde_json::Value> {
    let mut changes = Vec::with_capacity(pending.len());
    for change in pending {
        if change.operation == ChangeType::Delete {
            changes.push(json!({
                "item_id": change.item_id.to_string(),
                "operation": change.operation,
                "payload": serde_json::Value::Null,
                "path": change.path,
                "name": change.name,
                "type_id": change.type_id,
                "base_seq": change.base_seq,
            }));
            continue;
        }
        let payload_enc = change.payload_enc.as_ref().expect("payload enc");
        let payload =
            super::crypto::decrypt_payload(master_key, vault_id, change.item_id, payload_enc)
                .expect("decrypt payload");
        let payload_json = serde_json::to_value(payload).expect("payload json");
        changes.push(json!({
            "item_id": change.item_id.to_string(),
            "operation": change.operation,
            "payload": payload_json,
            "path": change.path,
            "name": change.name,
            "type_id": change.type_id,
            "base_seq": change.base_seq,
        }));
    }
    changes
}
