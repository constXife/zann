use std::collections::HashSet;

use serde::Deserialize;
use tauri::State;
use uuid::Uuid;

use crate::infra::auth::ensure_access_token_for_context;
use crate::infra::config::{load_config, save_config};
use crate::infra::http::{auth_headers, decode_json_response, ensure_success};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{
    ApiResponse, VaultCreatePayload, VaultCreateRequest, VaultCreateResponse, VaultListRequest,
    VaultListResponse, VaultSummary,
};
use zann_core::crypto::SecretKey;
use zann_core::vault_crypto as core_crypto;
use zann_core::VaultsService;
use zann_db::local::{
    LocalItemRepo, LocalStorageRepo, LocalVault, LocalVaultRepo, PendingChangeRepo, SyncCursorRepo,
};
use zann_db::services::LocalServices;

pub async fn vault_list(
    state: State<'_, AppState>,
    req: VaultListRequest,
) -> Result<ApiResponse<Vec<VaultSummary>>, String> {
    Ok(match list_vaults(state, req.storage_id).await {
        Ok(data) => ApiResponse::ok(data),
        Err(message) => ApiResponse::err("vault_list_failed", &message),
    })
}

pub async fn vault_create(
    state: State<'_, AppState>,
    req: VaultCreateRequest,
) -> Result<ApiResponse<VaultSummary>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&req.storage_id).map_err(|_| "invalid storage id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let name = req.name.trim();
    if name.is_empty() {
        return Ok(ApiResponse::err("name_required", "name is required"));
    }
    let kind = req
        .kind
        .clone()
        .unwrap_or_else(|| "personal".to_string())
        .to_lowercase();
    let cache_policy = req
        .cache_policy
        .clone()
        .unwrap_or_else(|| "full".to_string())
        .to_lowercase();
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = storage_repo
        .get(storage_id)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "storage not found".to_string())?;
    if storage.kind == "remote" {
        match create_remote_vault(
            &state,
            &storage,
            master_key.as_ref(),
            name,
            &kind,
            &cache_policy,
        )
        .await
        {
            Ok(vault) => Ok(ApiResponse::ok(vault)),
            Err(err) => Ok(ApiResponse::err("remote_error", &err)),
        }
    } else {
        let is_default = req.is_default.unwrap_or(false);
        let services = LocalServices::new(&state.pool, master_key.as_ref());
        match services
            .create_vault(storage_id, name, &kind, is_default)
            .await
        {
            Ok(vault) => Ok(ApiResponse::ok(VaultSummary {
                id: vault.id.to_string(),
                name: vault.name,
                kind: vault.kind,
                is_default: vault.is_default,
            })),
            Err(err) => Ok(ApiResponse::err(&err.kind, &err.message)),
        }
    }
}

pub async fn vault_reset_personal(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = storage_repo
        .get(storage_uuid)
        .await
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "storage not found".to_string())?;
    if storage.kind != "remote" {
        return Ok(ApiResponse::err(
            "storage_not_remote",
            "storage is not remote",
        ));
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
        Some(storage_uuid),
    )
    .await?;
    save_config(&state.root, &config).map_err(|err| err.to_string())?;

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
    let personal_vaults = vaults
        .vaults
        .into_iter()
        .filter(|vault| vault.kind == "personal")
        .collect::<Vec<_>>();

    for vault in &personal_vaults {
        let delete_url = format!("{}/v1/vaults/{}", addr.trim_end_matches('/'), vault.id);
        let resp = client
            .delete(delete_url)
            .headers(headers.clone())
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if let Err(err) = ensure_success(resp).await {
            return Ok(ApiResponse::err("vault_delete_failed", &err));
        }
    }

    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);
    let local_personal = vault_repo
        .list_by_storage(storage_uuid)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .filter(|vault| vault.kind == "personal")
        .map(|vault| vault.id)
        .collect::<Vec<_>>();
    let mut personal_ids = HashSet::new();
    for vault in local_personal {
        personal_ids.insert(vault);
    }
    for vault in &personal_vaults {
        let vault_id = Uuid::parse_str(&vault.id).map_err(|_| "invalid vault id")?;
        personal_ids.insert(vault_id);
    }
    for vault_id in personal_ids {
        let _ = item_repo
            .delete_by_storage_vault(storage_uuid, vault_id)
            .await;
        let _ = pending_repo
            .delete_by_storage_vault(storage_uuid, vault_id)
            .await;
        let _ = cursor_repo
            .delete_by_storage_vault(&storage_id, &vault_id.to_string())
            .await;
        let _ = vault_repo
            .delete_by_storage_vault(storage_uuid, vault_id)
            .await;
    }

    let mut config_updated = false;
    for (_, ctx) in config.contexts.iter_mut() {
        if ctx.storage_id.as_deref() == Some(&storage_id)
            || ctx.addr.trim_end_matches('/') == addr.trim_end_matches('/')
        {
            if ctx.expected_master_key_fp.take().is_some() {
                config_updated = true;
            }
        }
    }
    if config_updated {
        let _ = save_config(&state.root, &config);
    }

    Ok(ApiResponse::ok(()))
}

async fn list_vaults(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<Vec<VaultSummary>, String> {
    ensure_unlocked(&state).await?;
    let storage_id = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let vaults = services
        .list_vaults(storage_id)
        .await
        .map_err(|err| err.message)?;
    Ok(vaults
        .into_iter()
        .map(|vault| VaultSummary {
            id: vault.id.to_string(),
            name: vault.name,
            kind: vault.kind,
            is_default: vault.is_default,
        })
        .collect())
}

fn slugify_name(name: &str) -> String {
    let mut slug = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    slug.trim_matches('-')
        .to_string()
        .chars()
        .take(48)
        .collect::<String>()
        .trim()
        .to_string()
}

#[derive(Deserialize)]
struct RemoteErrorBody {
    error: String,
}

async fn create_remote_vault(
    state: &AppState,
    storage: &zann_db::local::LocalStorage,
    master_key: &SecretKey,
    name: &str,
    kind: &str,
    cache_policy: &str,
) -> Result<VaultSummary, String> {
    let kind = match kind {
        "personal" | "shared" => kind,
        _ => "personal",
    };
    let cache_policy = match cache_policy {
        "full" | "metadata_only" | "none" => cache_policy,
        _ => "full",
    };
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
    let storage_uuid = storage.id;
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

    let mut slug = slugify_name(name);
    if slug.is_empty() {
        slug = Uuid::now_v7().to_string();
    }
    let client_vault_id = Uuid::now_v7();
    let vault_key = SecretKey::generate();
    let vault_key_enc = if kind == "personal" {
        Some(
            core_crypto::encrypt_vault_key(master_key, client_vault_id, &vault_key)
                .map_err(|err| err.to_string())?,
        )
    } else {
        None
    };
    let payload = VaultCreatePayload {
        id: Some(client_vault_id.to_string()),
        slug,
        name: name.to_string(),
        kind: kind.to_string(),
        cache_policy: cache_policy.to_string(),
        vault_key_enc,
        tags: None,
    };
    let url = format!("{}/v1/vaults", addr.trim_end_matches('/'));
    let resp = client
        .post(url)
        .headers(auth_headers(&access_token)?)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(parsed) = serde_json::from_str::<RemoteErrorBody>(&body) {
            return Err(parsed.error);
        }
        return Err(format!("{status} {body}"));
    }
    let created = resp
        .json::<VaultCreateResponse>()
        .await
        .map_err(|err| err.to_string())?;
    let vault_id = Uuid::parse_str(&created.id).map_err(|err| err.to_string())?;
    if kind == "personal" && vault_id != client_vault_id {
        return Err("server did not honor vault id".to_string());
    }
    let (vault_key_enc_local, wrap_type) = if kind == "personal" {
        let vault_key_enc = core_crypto::encrypt_vault_key(master_key, vault_id, &vault_key)
            .map_err(|err| err.to_string())?;
        (vault_key_enc, "remote_strict")
    } else {
        (created.vault_key_enc.clone(), "remote_server")
    };
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let record = LocalVault {
        id: vault_id,
        storage_id: storage_uuid,
        name: created.name.clone(),
        kind: created.kind.clone(),
        is_default: false,
        vault_key_enc: vault_key_enc_local,
        key_wrap_type: wrap_type.to_string(),
        last_synced_at: None,
        server_seq: 0,
    };
    let _ = vault_repo.create(&record).await;
    Ok(VaultSummary {
        id: created.id,
        name: created.name,
        kind: created.kind,
        is_default: false,
    })
}
