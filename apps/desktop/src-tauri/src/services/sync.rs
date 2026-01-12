use chrono::Utc;
use tauri::State;
use uuid::Uuid;
use zann_db::local::{
    KeyWrapType, LocalItemHistoryRepo, LocalItemRepo, LocalPendingChange, LocalStorage,
    LocalStorageRepo, LocalSyncCursor, LocalVaultRepo, PendingChangeRepo, SyncCursorRepo,
};

use crate::crypto::{decrypt_vault_key_with_master, vault_key_aad};
use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::infra::remote::fetch_system_info;
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, SyncPullRequest, SyncPullResponse, SyncPushChange, SyncPushRequest,
    SyncPushResponse, SyncSharedPullResponse, SyncSharedPushRequest, VaultListResponse,
};
use zann_core::crypto::{encrypt_blob, SecretKey};
use zann_core::{StorageKind, VaultEncryptionType, VaultKind};

use crate::services::sync_helpers::{
    apply_pull_change, apply_push_applied, apply_shared_pull_change, build_remote_storage,
    build_shared_push_changes, ensure_local_vaults, fetch_vault_details, handle_sync_conflict,
    key_fingerprint,
};

pub async fn remote_sync(
    storage_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<ApiResponse<serde_json::Value>, String> {
    let master_key_arc = state.master_key.read().await.clone();
    let Some(master_key) = master_key_arc else {
        return Ok(ApiResponse::err("vault_locked", "unlock required"));
    };

    let mut config = load_config(&state.root).unwrap_or_else(|_| Default::default());
    let context_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "desktop".to_string());
    let Some(context) = config.contexts.get(&context_name).cloned() else {
        return Ok(ApiResponse::err("context_missing", "context not found"));
    };
    let master_fp = key_fingerprint(master_key.as_ref());
    let expected_master_fp = context.expected_master_key_fp.clone();
    let personal_allowed = expected_master_fp
        .as_deref()
        .map(|expected| expected == master_fp)
        .unwrap_or(true);
    let mut expected_fp_updated = false;
    let mut locked_vaults: Vec<String> = Vec::new();
    let addr = context.addr.clone();
    let storage_uuid = storage_id
        .or(context.storage_id.clone())
        .and_then(|value| Uuid::parse_str(&value).ok())
        .unwrap_or_else(Uuid::nil);
    let storage_uuid = if storage_uuid.is_nil() {
        let storage_repo = LocalStorageRepo::new(&state.pool);
        let existing = storage_repo
            .list()
            .await
            .ok()
            .and_then(|storages| {
                storages
                    .into_iter()
                    .find(|storage| storage.server_url.as_deref() == Some(addr.as_str()))
            })
            .map(|storage| storage.id)
            .unwrap_or_else(Uuid::now_v7);
        existing
    } else {
        storage_uuid
    };

    let client = reqwest::Client::new();
    let access_token = ensure_access_token_for_context(
        &client,
        &addr,
        &context_name,
        &mut config,
        Some(storage_uuid),
    )
    .await?;
    save_config(&state.root, &config).map_err(|err| err.to_string())?;

    let system_info = match fetch_system_info(&client, &addr).await {
        Ok(info) => Some(info),
        Err(err) => {
            return Ok(ApiResponse::err("system_info_failed", &err));
        }
    };
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let existing_storage = storage_repo
        .get(storage_uuid)
        .await
        .map_err(|err| err.to_string())?;
    if let (Some(info), Some(storage)) = (system_info.as_ref(), existing_storage.as_ref()) {
        if let Some(stored_fp) = storage.server_fingerprint.as_deref() {
            if stored_fp != info.server_fingerprint {
                let pending_repo = PendingChangeRepo::new(&state.pool);
                let pending = pending_repo
                    .list_by_storage(storage_uuid)
                    .await
                    .map_err(|err| err.to_string())?;
                if !pending.is_empty() {
                    return Ok(ApiResponse::err(
                        "server_fingerprint_changed",
                        &format!(
                            "server reset detected (old={}, new={}) with {} pending changes",
                            stored_fp,
                            info.server_fingerprint,
                            pending.len()
                        ),
                    ));
                }

                let item_repo = LocalItemRepo::new(&state.pool);
                let vault_repo = LocalVaultRepo::new(&state.pool);
                let cursor_repo = SyncCursorRepo::new(&state.pool);
                let _ = item_repo.delete_by_storage(storage_uuid).await;
                let _ = vault_repo.delete_by_storage(storage_uuid).await;
                let _ = cursor_repo.delete_by_storage(storage_uuid).await;
                let _ = pending_repo.delete_by_storage(storage_uuid).await;
            }
        }
    }

    let headers = auth_headers(&access_token)?;
    let vaults_url = format!("{}/v1/vaults", addr.trim_end_matches('/'));
    let vaults_resp = client
        .get(vaults_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let vaults_resp = match ensure_success(vaults_resp).await {
        Ok(response) => response,
        Err(err) => return Ok(ApiResponse::err("vault_list_failed", &err)),
    };
    let vaults = decode_json_response::<VaultListResponse>(vaults_resp).await?;
    let vault_details = match fetch_vault_details(&client, &headers, &addr, &vaults).await {
        Ok(details) => details,
        Err(message) => return Ok(ApiResponse::err("vault_get_failed", &message)),
    };

    let storage = build_remote_storage(storage_uuid, &addr, system_info.as_ref(), &config);
    storage_repo
        .upsert(&storage)
        .await
        .map_err(|err| err.to_string())?;

    let vault_repo = LocalVaultRepo::new(&state.pool);
    ensure_local_vaults(&vault_repo, storage_uuid, &vault_details).await?;

    for vault in &vault_details {
        let encryption_type = VaultEncryptionType::try_from(vault.encryption_type)
            .map_err(|_| "invalid vault encryption type".to_string())?;
        let kind = VaultKind::try_from(vault.kind)
            .map_err(|_| "invalid vault kind".to_string())?;
        if encryption_type != VaultEncryptionType::Client || kind != VaultKind::Personal {
            continue;
        }
        if !personal_allowed {
            locked_vaults.push(vault.id.clone());
            continue;
        }
        if !vault.vault_key_enc.is_empty() {
            continue;
        }
        let vault_id = Uuid::parse_str(&vault.id).map_err(|err| err.to_string())?;
        let Ok(Some(local_vault)) = vault_repo.get_by_id(storage_uuid, vault_id).await else {
            continue;
        };
        if !local_vault.vault_key_enc.is_empty() {
            continue;
        }
        let vault_key = SecretKey::generate();
        let aad = vault_key_aad(vault_id);
        let blob = encrypt_blob(master_key.as_ref(), vault_key.as_bytes(), &aad)
            .map_err(|err| err.to_string())?;
        let master_fp = key_fingerprint(master_key.as_ref());
        let payload = serde_json::json!({ "vault_key_enc": blob.to_bytes() });
        let url = format!("{}/v1/vaults/{}/key", addr.trim_end_matches('/'), vault.id);
        let resp = client
            .put(url)
            .headers(headers.clone())
            .json(&payload)
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if let Err(err) = ensure_success(resp).await {
            return Ok(ApiResponse::err("vault_key_update_failed", &err));
        }
        if let Some(ctx) = config.contexts.get_mut(&context_name) {
            if ctx.expected_master_key_fp.as_deref() != Some(master_fp.as_str()) {
                ctx.expected_master_key_fp = Some(master_fp.clone());
                expected_fp_updated = true;
            }
        }
        let _ = vault_repo
            .update_key(storage_uuid, vault_id, &blob.to_bytes(), KeyWrapType::RemoteStrict)
            .await;
    }

    let item_repo = LocalItemRepo::new(&state.pool);
    let history_repo = LocalItemHistoryRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);
    let mut applied_total = 0;
    for vault in &vault_details {
        let vault_id = Uuid::parse_str(&vault.id).map_err(|err| err.to_string())?;
        let Ok(Some(local_vault)) = vault_repo.get_by_id(storage_uuid, vault_id).await else {
            continue;
        };
        let encryption_type = VaultEncryptionType::try_from(vault.encryption_type)
            .map_err(|_| "invalid vault encryption type".to_string())?;
        let kind = VaultKind::try_from(vault.kind)
            .map_err(|_| "invalid vault kind".to_string())?;
        let should_be_shared =
            encryption_type == VaultEncryptionType::Server && kind == VaultKind::Shared;
        let desired_wrap = if should_be_shared {
            KeyWrapType::RemoteServer
        } else {
            KeyWrapType::RemoteStrict
        };
        if local_vault.key_wrap_type != desired_wrap {
            let key_bytes = if desired_wrap == KeyWrapType::RemoteServer {
                Vec::new()
            } else {
                local_vault.vault_key_enc.clone()
            };
            let _ = vault_repo
                .update_key(storage_uuid, vault_id, &key_bytes, desired_wrap)
                .await;
        }
        let is_shared = should_be_shared;
        if !is_shared && !personal_allowed {
            locked_vaults.push(vault.id.clone());
            continue;
        }
        let vault_key = if is_shared {
            None
        } else {
            match decrypt_vault_key_with_master(master_key.as_ref(), &local_vault) {
                Ok(key) => {
                    if local_vault.key_wrap_type != KeyWrapType::RemoteStrict {
                        let _ = vault_repo
                            .update_key(
                                storage_uuid,
                                vault_id,
                                &local_vault.vault_key_enc,
                                KeyWrapType::RemoteStrict,
                            )
                            .await;
                    }
                    if let Some(ctx) = config.contexts.get_mut(&context_name) {
                        if ctx.expected_master_key_fp.as_deref() != Some(master_fp.as_str()) {
                            ctx.expected_master_key_fp = Some(master_fp.clone());
                            expected_fp_updated = true;
                        }
                    }
                    Some(key)
                }
                Err(_err) => {
                    locked_vaults.push(vault.id.clone());
                    continue;
                }
            }
        };

        let cursor_row = cursor_repo
            .get(storage_uuid, vault_id)
            .await
            .map_err(|err| err.to_string())?
            .unwrap_or(LocalSyncCursor {
                storage_id: storage_uuid,
                vault_id,
                cursor: None,
                last_sync_at: None,
            });

        let mut cursor_value = cursor_row.cursor.clone();
        let pending = pending_repo
            .list_by_storage_vault(storage_uuid, vault_id)
            .await
            .map_err(|err| err.to_string())?;
        if !pending.is_empty() {
            let mut pending_by_item: std::collections::HashMap<String, LocalPendingChange> =
                std::collections::HashMap::new();
            for change in &pending {
                pending_by_item.insert(change.item_id.to_string(), change.clone());
            }
            let (push_url, body) = if is_shared {
                let changes = build_shared_push_changes(&pending, master_key.as_ref(), vault_id)?;
                (
                    format!("{}/v1/sync/shared/push", addr.trim_end_matches('/')),
                    serde_json::to_value(SyncSharedPushRequest {
                        vault_id: vault.id.clone(),
                        changes,
                    })
                    .map_err(|err| err.to_string())?,
                )
            } else {
                let changes: Vec<SyncPushChange> = pending
                    .iter()
                    .map(|change| SyncPushChange {
                        item_id: change.item_id.to_string(),
                        operation: change.operation.as_i32(),
                        payload_enc: change.payload_enc.clone(),
                        checksum: change.checksum.clone(),
                        path: change.path.clone(),
                        name: change.name.clone(),
                        type_id: change.type_id.clone(),
                        base_seq: change.base_seq,
                    })
                    .collect();
                (
                    format!("{}/v1/sync/push", addr.trim_end_matches('/')),
                    serde_json::to_value(SyncPushRequest {
                        vault_id: vault.id.clone(),
                        changes,
                    })
                    .map_err(|err| err.to_string())?,
                )
            };
            let resp = client
                .post(&push_url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await
                .map_err(|err| err.to_string())?;
            let resp = match ensure_success(resp).await {
                Ok(response) => response,
                Err(err) => return Ok(ApiResponse::err("sync_push_failed", &err)),
            };
            let push_resp = resp
                .json::<SyncPushResponse>()
                .await
                .map_err(|err| err.to_string())?;
            if !push_resp.applied_changes.is_empty() {
                let _ = apply_push_applied(
                    &item_repo,
                    storage_uuid,
                    vault_id,
                    &push_resp.applied_changes,
                )
                .await;
            }
            if !push_resp.applied.is_empty() {
                let ids: Vec<Uuid> = push_resp
                    .applied
                    .iter()
                    .filter_map(|item_id| pending_by_item.get(item_id).map(|change| change.id))
                    .collect();
                let _ = pending_repo.delete_by_ids(&ids).await;
            }
            if !push_resp.conflicts.is_empty() {
                let mut conflict_pending_ids = Vec::new();
                for conflict in &push_resp.conflicts {
                    if let Some(change) = pending_by_item.get(&conflict.item_id) {
                        let _ = handle_sync_conflict(&item_repo, storage_uuid, vault_id, change)
                            .await
                            .ok();
                        conflict_pending_ids.push(change.id);
                    }
                }
                if !conflict_pending_ids.is_empty() {
                    let _ = pending_repo.delete_by_ids(&conflict_pending_ids).await;
                }
            }
            cursor_value = Some(push_resp.new_cursor.clone());
        }

        loop {
            if is_shared {
                let pull_req = SyncPullRequest {
                    vault_id: vault.id.clone(),
                    cursor: cursor_value.clone(),
                    limit: 100,
                };
                let pull_url = format!("{}/v1/sync/shared/pull", addr.trim_end_matches('/'));
                let resp = client
                    .post(&pull_url)
                    .headers(headers.clone())
                    .json(&pull_req)
                    .send()
                    .await
                    .map_err(|err| err.to_string())?;
                let resp = match ensure_success(resp).await {
                    Ok(response) => response,
                    Err(_) => break,
                };
                let pull = resp
                    .json::<SyncSharedPullResponse>()
                    .await
                    .map_err(|err| err.to_string())?;
                for change in &pull.changes {
                    if apply_shared_pull_change(
                        &item_repo,
                        &history_repo,
                        master_key.as_ref(),
                        storage_uuid,
                        vault_id,
                        change,
                    )
                    .await
                    .unwrap_or(false)
                    {
                        applied_total += 1;
                    }
                }
                cursor_value = Some(pull.next_cursor.clone());
                if !pull.has_more {
                    break;
                }
            } else {
                let pull_req = SyncPullRequest {
                    vault_id: vault.id.clone(),
                    cursor: cursor_value.clone(),
                    limit: 100,
                };
                let pull_url = format!("{}/v1/sync/pull", addr.trim_end_matches('/'));
                let resp = client
                    .post(&pull_url)
                    .headers(headers.clone())
                    .json(&pull_req)
                    .send()
                    .await
                    .map_err(|err| err.to_string())?;
                let resp = match ensure_success(resp).await {
                    Ok(response) => response,
                    Err(_) => break,
                };
                let pull = resp.json::<SyncPullResponse>().await.map_err(|err| err.to_string())?;

                let Some(vault_key) = vault_key.as_ref() else {
                    break;
                };
                for change in &pull.changes {
                    if apply_pull_change(
                        &item_repo,
                        &history_repo,
                        vault_key,
                        storage_uuid,
                        vault_id,
                        change,
                    )
                        .await
                        .unwrap_or(false)
                    {
                        applied_total += 1;
                    }
                }

                cursor_value = Some(pull.next_cursor.clone());
                if !pull.has_more {
                    break;
                }
            }
        }

        let cursor = LocalSyncCursor {
            storage_id: storage_uuid,
            vault_id,
            cursor: cursor_value.clone(),
            last_sync_at: Some(Utc::now()),
        };
        cursor_repo
            .upsert(&cursor)
            .await
            .map_err(|err| err.to_string())?;
    }

    if expected_fp_updated {
        let _ = save_config(&state.root, &config);
    }

    Ok(ApiResponse::ok(serde_json::json!({
        "applied": applied_total,
        "locked_vaults": locked_vaults,
    })))
}

pub async fn remote_reset(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let Some(storage) = storage_repo
        .get(storage_uuid)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Ok(ApiResponse::err("storage_not_found", "storage not found"));
    };
    if storage.kind != StorageKind::Remote {
        return Ok(ApiResponse::err(
            "not_remote",
            "reset only supported for remote storages",
        ));
    }
    let Some(server_url) = storage.server_url.as_deref() else {
        return Ok(ApiResponse::err("invalid_storage", "server_url missing"));
    };

    let client = reqwest::Client::new();
    let info = fetch_system_info(&client, server_url)
        .await
        .map_err(|err| err.to_string())?;

    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);
    let _ = pending_repo.delete_by_storage(storage_uuid).await;
    let _ = cursor_repo.delete_by_storage(storage_uuid).await;
    let _ = item_repo.delete_by_storage(storage_uuid).await;
    let _ = vault_repo.delete_by_storage(storage_uuid).await;

    let updated = LocalStorage {
        server_name: info.server_name.clone(),
        server_fingerprint: Some(info.server_fingerprint.clone()),
        personal_vaults_enabled: info.personal_vaults_enabled,
        ..storage
    };
    storage_repo
        .upsert(&updated)
        .await
        .map_err(|err| err.to_string())?;

    Ok(ApiResponse::ok(()))
}

pub async fn sync_reset_cursor(
    storage_id: String,
    state: State<'_, AppState>,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let Some(storage) = storage_repo
        .get(storage_uuid)
        .await
        .map_err(|err| err.to_string())?
    else {
        return Ok(ApiResponse::err("storage_not_found", "storage not found"));
    };
    if storage.kind != StorageKind::Remote {
        return Ok(ApiResponse::err(
            "not_remote",
            "reset only supported for remote storages",
        ));
    }

    let cursor_repo = SyncCursorRepo::new(&state.pool);
    cursor_repo.delete_by_storage(storage_uuid).await
        .map_err(|err| err.to_string())?;

    Ok(ApiResponse::ok(()))
}
