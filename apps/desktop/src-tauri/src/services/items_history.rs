use serde::Deserialize;
use tauri::State;
use uuid::Uuid;

use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, ItemHistoryDetail, ItemHistoryGetRequest, ItemHistoryListRequest,
    ItemHistoryRestoreRequest, ItemHistorySummary,
};
use zann_db::local::{LocalStorageRepo, LocalVaultRepo};
use zann_db::services::LocalServices;

pub async fn items_history_list(
    state: State<'_, AppState>,
    req: ItemHistoryListRequest,
) -> Result<ApiResponse<Vec<ItemHistorySummary>>, String> {
    Ok(match list_item_history(state, req).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => {
            if message == "history_unavailable_shared" {
                ApiResponse::err("history_unavailable_shared", &message)
            } else {
                ApiResponse::err("history_list_failed", &message)
            }
        }
    })
}

pub async fn items_history_get(
    state: State<'_, AppState>,
    req: ItemHistoryGetRequest,
) -> Result<ApiResponse<ItemHistoryDetail>, String> {
    Ok(match get_item_history(state, req).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => {
            if message == "history_unavailable_shared" {
                ApiResponse::err("history_unavailable_shared", &message)
            } else {
                ApiResponse::err("history_get_failed", &message)
            }
        }
    })
}

pub async fn items_history_restore(
    state: State<'_, AppState>,
    req: ItemHistoryRestoreRequest,
) -> Result<ApiResponse<()>, String> {
    Ok(match restore_item_history(state, req).await {
        Ok(()) => ApiResponse::ok(()),
        Err(message) => ApiResponse::err("history_restore_failed", &message),
    })
}

async fn list_item_history(
    state: State<'_, AppState>,
    req: ItemHistoryListRequest,
) -> Result<Vec<ItemHistorySummary>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let vault_id = Uuid::parse_str(&req.vault_id).map_err(|_| "invalid vault id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = storage_repo
        .get(storage_id)
        .await
        .map_err(|_| "failed to get storage")?
        .ok_or_else(|| "storage not found".to_string())?;
    if storage.kind != "remote" {
        return Ok(Vec::new());
    }

    let vault_repo = LocalVaultRepo::new(&state.pool);
    let vault_uuid = vault_id;
    let vault = vault_repo
        .get_by_id(storage_id, vault_uuid)
        .await
        .map_err(|_| "failed to get vault")?
        .ok_or_else(|| "vault not found".to_string())?;

    let mut config = load_config(&state.root).unwrap_or_default();
    let context_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "desktop".to_string());
    let addr = storage
        .server_url
        .clone()
        .or_else(|| config.contexts.get(&context_name).map(|ctx| ctx.addr.clone()))
        .ok_or_else(|| "server url missing".to_string())?;
    let client = reqwest::Client::new();
    let access_token = ensure_access_token_for_context(
        &client,
        &addr,
        &context_name,
        &mut config,
        Some(storage_id),
    )
    .await?;
    save_config(&state.root, &config).map_err(|err| err.to_string())?;

    let limit = req.limit.unwrap_or(5).clamp(1, 5);
    let base = if vault.kind == "shared" && vault.key_wrap_type == "remote_server" {
        format!(
            "{}/v1/shared/items/{}/versions",
            addr.trim_end_matches('/'),
            item_id
        )
    } else {
        format!(
            "{}/v1/vaults/{}/items/{}/versions",
            addr.trim_end_matches('/'),
            vault_id,
            item_id
        )
    };
    let url = format!("{base}?limit={limit}");
    let response = client
        .get(url)
        .headers(auth_headers(&access_token)?)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if response.status() == reqwest::StatusCode::FORBIDDEN
        && vault.kind == "shared"
        && vault.key_wrap_type == "remote_server"
    {
        return Err("history_unavailable_shared".to_string());
    }
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("{status} {body}"));
    }
    let list = decode_json_response::<RemoteHistoryListResponse>(response).await?;
    Ok(list
        .versions
        .into_iter()
        .map(|entry| ItemHistorySummary {
            version: entry.version,
            checksum: entry.checksum,
            change_type: entry.change_type,
            changed_by_name: entry.changed_by_name,
            changed_by_email: entry.changed_by_email,
            created_at: entry.created_at,
        })
        .collect())
}

async fn get_item_history(
    state: State<'_, AppState>,
    req: ItemHistoryGetRequest,
) -> Result<ItemHistoryDetail, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let vault_id = Uuid::parse_str(&req.vault_id).map_err(|_| "invalid vault id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = storage_repo
        .get(storage_id)
        .await
        .map_err(|_| "failed to get storage")?
        .ok_or_else(|| "storage not found".to_string())?;
    if storage.kind != "remote" {
        return Err("history unavailable for local storage".to_string());
    }
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let vault = vault_repo
        .get_by_id(storage_id, vault_id)
        .await
        .map_err(|_| "failed to get vault")?
        .ok_or_else(|| "vault not found".to_string())?;

    let mut config = load_config(&state.root).unwrap_or_default();
    let context_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "desktop".to_string());
    let addr = storage
        .server_url
        .clone()
        .or_else(|| config.contexts.get(&context_name).map(|ctx| ctx.addr.clone()))
        .ok_or_else(|| "server url missing".to_string())?;
    let client = reqwest::Client::new();
    let access_token = ensure_access_token_for_context(
        &client,
        &addr,
        &context_name,
        &mut config,
        Some(storage_id),
    )
    .await?;
    save_config(&state.root, &config).map_err(|err| err.to_string())?;

    let url = if vault.kind == "shared" && vault.key_wrap_type == "remote_server" {
        format!(
            "{}/v1/shared/items/{}/versions/{}",
            addr.trim_end_matches('/'),
            item_id,
            req.version
        )
    } else {
        format!(
            "{}/v1/vaults/{}/items/{}/versions/{}",
            addr.trim_end_matches('/'),
            vault_id,
            item_id,
            req.version
        )
    };
    let response = client
        .get(url)
        .headers(auth_headers(&access_token)?)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if response.status() == reqwest::StatusCode::FORBIDDEN
        && vault.kind == "shared"
        && vault.key_wrap_type == "remote_server"
    {
        return Err("history_unavailable_shared".to_string());
    }
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("{status} {body}"));
    }
    let payload = if vault.kind == "shared" && vault.key_wrap_type == "remote_server" {
        let remote = decode_json_response::<SharedHistoryDetailResponse>(response).await?;
        serde_json::from_value(remote.payload).map_err(|err| err.to_string())?
    } else {
        let remote = decode_json_response::<RemoteHistoryDetailResponse>(response).await?;
        let master_key = state
            .master_key
            .read()
            .await
            .clone()
            .ok_or_else(|| "vault is locked".to_string())?;
        let services = LocalServices::new(&state.pool, master_key.as_ref());
        services
            .decrypt_payload_for_item(storage_id, vault_id, item_id, &remote.payload_enc)
            .await
            .map_err(|err| err.message)?
    };

    Ok(ItemHistoryDetail {
        version: req.version,
        payload: serde_json::to_value(payload).map_err(|err| err.to_string())?,
    })
}

async fn restore_item_history(
    state: State<'_, AppState>,
    req: ItemHistoryRestoreRequest,
) -> Result<(), String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let vault_id = Uuid::parse_str(&req.vault_id).map_err(|_| "invalid vault id")?;
    let item_id = Uuid::parse_str(&req.item_id).map_err(|_| "invalid item id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = storage_repo
        .get(storage_id)
        .await
        .map_err(|_| "failed to get storage")?
        .ok_or_else(|| "storage not found".to_string())?;
    if storage.kind != "remote" {
        return Err("history unavailable for local storage".to_string());
    }

    let mut config = load_config(&state.root).unwrap_or_default();
    let context_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "desktop".to_string());
    let addr = storage
        .server_url
        .clone()
        .or_else(|| config.contexts.get(&context_name).map(|ctx| ctx.addr.clone()))
        .ok_or_else(|| "server url missing".to_string())?;
    let client = reqwest::Client::new();
    let access_token = ensure_access_token_for_context(
        &client,
        &addr,
        &context_name,
        &mut config,
        Some(storage_id),
    )
    .await?;
    save_config(&state.root, &config).map_err(|err| err.to_string())?;

    let url = format!(
        "{}/v1/vaults/{}/items/{}/versions/{}/restore",
        addr.trim_end_matches('/'),
        vault_id,
        item_id,
        req.version
    );
    let response = client
        .post(url)
        .headers(auth_headers(&access_token)?)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("{status} {body}"));
    }
    Ok(())
}

#[derive(Deserialize)]
struct RemoteHistoryListResponse {
    versions: Vec<RemoteHistorySummary>,
}

#[derive(Deserialize)]
struct RemoteHistorySummary {
    version: i64,
    checksum: String,
    change_type: String,
    #[serde(default)]
    changed_by_name: Option<String>,
    changed_by_email: String,
    created_at: String,
}

#[derive(Deserialize)]
struct RemoteHistoryDetailResponse {
    payload_enc: Vec<u8>,
}

#[derive(Deserialize)]
struct SharedHistoryDetailResponse {
    payload: serde_json::Value,
}
