use tauri::State;
use tauri_plugin_biometry::BiometryExt;
use uuid::Uuid;
use zann_core::StoragesService;
use zann_db::local::{
    LocalItemRepo, LocalStorageRepo, LocalVaultRepo, PendingChangeRepo, SyncCursorRepo,
};
use zann_db::services::LocalServices;

use crate::infra::config::{load_config, save_config};
use crate::state::{ensure_unlocked, AppState};
use crate::types::{ApiResponse, AppVersionResponse, StorageInfoResponse, StorageSummary};

pub async fn storages_list(
    state: State<'_, AppState>,
) -> Result<ApiResponse<Vec<StorageSummary>>, String> {
    ensure_unlocked(&state).await?;
    let master_key = state
        .master_key
        .read()
        .await
        .clone()
        .ok_or_else(|| "vault is locked".to_string())?;
    let services = LocalServices::new(&state.pool, master_key.as_ref());
    let storages = services
        .list_storages()
        .await
        .map_err(|err| err.message)?;
    Ok(ApiResponse::ok(
        storages
            .into_iter()
            .map(|storage| StorageSummary {
                id: storage.id.to_string(),
                name: storage.name,
                kind: storage.kind.as_str().to_string(),
                server_url: storage.server_url,
                server_name: storage.server_name,
                account_subject: storage.account_subject,
                personal_vaults_enabled: storage.personal_vaults_enabled,
            })
            .collect(),
    ))
}

pub async fn storage_info(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<ApiResponse<StorageInfoResponse>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = match storage_repo.get(storage_uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(ApiResponse::err("storage_not_found", "storage not found")),
        Err(err) => return Ok(ApiResponse::err("db_error", &err.to_string())),
    };

    let mut file_path = None;
    let mut file_size = None;
    let mut last_modified = None;
    let mut last_synced = None;
    let mut fingerprint = None;

    if storage.kind == "local" {
        let db_path = crate::state::local_db_path(&state.root);
        file_path = Some(db_path.display().to_string());
        if let Ok(metadata) = std::fs::metadata(&db_path) {
            file_size = Some(metadata.len());
            if let Ok(modified) = metadata.modified() {
                let datetime: chrono::DateTime<chrono::Utc> = modified.into();
                last_modified = Some(datetime.to_rfc3339());
            }
        }
    } else {
        let cursor_repo = SyncCursorRepo::new(&state.pool);
        let vault_repo = LocalVaultRepo::new(&state.pool);
        if let Ok(vaults) = vault_repo.list_by_storage(storage_uuid).await {
            let mut latest_sync: Option<chrono::DateTime<chrono::Utc>> = None;
            for vault in vaults {
                if let Ok(Some(cursor)) = cursor_repo.get(&storage_id, &vault.id.to_string()).await
                {
                    if let Some(sync_at) = cursor.last_sync_at {
                        if latest_sync.is_none() || sync_at > latest_sync.unwrap() {
                            latest_sync = Some(sync_at);
                        }
                    }
                }
            }
            last_synced = latest_sync.map(|dt| dt.to_rfc3339());
        }

        fingerprint = storage.server_fingerprint.clone();
    }

    Ok(ApiResponse::ok(StorageInfoResponse {
        id: storage.id.to_string(),
        name: storage.name,
        kind: storage.kind,
        file_path,
        file_size,
        last_modified,
        server_url: storage.server_url,
        server_name: storage.server_name,
        account_subject: storage.account_subject,
        last_synced,
        fingerprint,
    }))
}

pub async fn storage_delete(
    state: State<'_, AppState>,
    storage_id: String,
    move_to_trash: bool,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = match storage_repo.get(storage_uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(ApiResponse::err("storage_not_found", "storage not found")),
        Err(err) => return Ok(ApiResponse::err("db_error", &err.to_string())),
    };

    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);

    if let Err(err) = pending_repo.delete_by_storage(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete pending changes: {err}"),
        ));
    }
    if let Err(err) = cursor_repo.delete_by_storage(&storage_id).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete sync cursors: {err}"),
        ));
    }
    if let Err(err) = item_repo.delete_by_storage(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete items: {err}"),
        ));
    }
    if let Err(err) = vault_repo.delete_by_storage(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete vaults: {err}"),
        ));
    }
    if let Err(err) = storage_repo.delete(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete storage: {err}"),
        ));
    }

    if storage.kind == "remote" {
        if let Ok(mut config) = load_config(&state.root) {
            let contexts_to_remove: Vec<String> = config
                .contexts
                .iter()
                .filter(|(_, ctx)| ctx.storage_id.as_deref() == Some(&storage_id))
                .map(|(name, _)| name.clone())
                .collect();

            for name in contexts_to_remove {
                config.contexts.remove(&name);
                if config.current_context.as_deref() == Some(&name) {
                    config.current_context = None;
                }
            }
            let _ = save_config(&state.root, &config);
        }
    }

    let _ = move_to_trash;

    Ok(ApiResponse::ok(()))
}

pub async fn storage_disconnect(
    state: State<'_, AppState>,
    storage_id: String,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = match storage_repo.get(storage_uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(ApiResponse::err("storage_not_found", "storage not found")),
        Err(err) => return Ok(ApiResponse::err("db_error", &err.to_string())),
    };

    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);

    if let Err(err) = pending_repo.delete_by_storage(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete pending changes: {err}"),
        ));
    }
    if let Err(err) = cursor_repo.delete_by_storage(&storage_id).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete sync cursors: {err}"),
        ));
    }
    if let Err(err) = item_repo.delete_by_storage(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete items: {err}"),
        ));
    }
    if let Err(err) = vault_repo.delete_by_storage(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete vaults: {err}"),
        ));
    }
    if let Err(err) = storage_repo.delete(storage_uuid).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to delete storage: {err}"),
        ));
    }

    if storage.kind == "remote" {
        if let Ok(mut config) = load_config(&state.root) {
            let contexts_to_remove: Vec<String> = config
                .contexts
                .iter()
                .filter(|(_, ctx)| ctx.storage_id.as_deref() == Some(&storage_id))
                .map(|(name, _)| name.clone())
                .collect();

            for name in contexts_to_remove {
                config.contexts.remove(&name);
                if config.current_context.as_deref() == Some(&name) {
                    config.current_context = None;
                }
            }
            let _ = save_config(&state.root, &config);
        }
    }

    Ok(ApiResponse::ok(()))
}

pub async fn storage_reveal(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    storage_id: String,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = match storage_repo.get(storage_uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(ApiResponse::err("storage_not_found", "storage not found")),
        Err(err) => return Ok(ApiResponse::err("db_error", &err.to_string())),
    };

    if storage.kind != "local" {
        return Ok(ApiResponse::err("not_local", "can only reveal local storages"));
    }

    let db_path = crate::state::local_db_path(&state.root);

    use tauri_plugin_shell::ShellExt;

    #[cfg(target_os = "macos")]
    let _ = app
        .shell()
        .command("open")
        .args(["-R", &db_path.display().to_string()])
        .spawn();

    #[cfg(target_os = "windows")]
    let _ = app
        .shell()
        .command("explorer")
        .args(["/select,", &db_path.display().to_string()])
        .spawn();

    #[cfg(target_os = "linux")]
    if let Some(parent) = db_path.parent() {
        let _ = app
            .shell()
            .command("xdg-open")
            .args([&parent.display().to_string()])
            .spawn();
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let _ = &app;

    Ok(ApiResponse::ok(()))
}

pub async fn storage_sign_out(
    state: State<'_, AppState>,
    storage_id: String,
    erase_cache: bool,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;
    let storage_uuid = Uuid::parse_str(&storage_id).map_err(|_| "invalid storage id")?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let storage = match storage_repo.get(storage_uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(ApiResponse::err("storage_not_found", "storage not found")),
        Err(err) => return Ok(ApiResponse::err("db_error", &err.to_string())),
    };

    if storage.kind != "remote" {
        return Ok(ApiResponse::err(
            "not_remote",
            "sign out only works for remote storages",
        ));
    }

    if let Ok(mut config) = load_config(&state.root) {
        for (_, ctx) in config.contexts.iter_mut() {
            if ctx.storage_id.as_deref() == Some(&storage_id) {
                ctx.tokens.clear();
                ctx.current_token = None;
            }
        }
        let _ = save_config(&state.root, &config);
    }

    if erase_cache {
        let item_repo = LocalItemRepo::new(&state.pool);
        let vault_repo = LocalVaultRepo::new(&state.pool);
        let cursor_repo = SyncCursorRepo::new(&state.pool);
        let pending_repo = PendingChangeRepo::new(&state.pool);

        let _ = pending_repo.delete_by_storage(storage_uuid).await;
        let _ = cursor_repo.delete_by_storage(&storage_id).await;
        let _ = item_repo.delete_by_storage(storage_uuid).await;
        let _ = vault_repo.delete_by_storage(storage_uuid).await;
    }

    if let Err(err) = storage_repo.update_account_info(storage_uuid, None).await {
        return Ok(ApiResponse::err(
            "db_error",
            &format!("failed to clear account info: {err}"),
        ));
    }

    Ok(ApiResponse::ok(()))
}

pub async fn local_clear_data(
    state: State<'_, AppState>,
    also_clear_remote_cache: bool,
    also_remove_connections: bool,
) -> Result<ApiResponse<()>, String> {
    ensure_unlocked(&state).await?;

    let storage_repo = LocalStorageRepo::new(&state.pool);
    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);

    let storages = storage_repo.list().await.map_err(|e| e.to_string())?;

    for storage in &storages {
        let should_clear = if storage.kind == "local" {
            true
        } else {
            also_clear_remote_cache
        };

        if should_clear {
            let _ = pending_repo.delete_by_storage(storage.id).await;
            let _ = cursor_repo.delete_by_storage(&storage.id.to_string()).await;
            let _ = item_repo.delete_by_storage(storage.id).await;
            let _ = vault_repo.delete_by_storage(storage.id).await;
        }

        if storage.kind == "local" || (storage.kind == "remote" && also_remove_connections) {
            let _ = storage_repo.delete(storage.id).await;
        }
    }

    if also_remove_connections {
        if let Ok(mut config) = load_config(&state.root) {
            config.contexts.clear();
            config.current_context = None;
            let _ = save_config(&state.root, &config);
        }
    }

    Ok(ApiResponse::ok(()))
}

pub async fn local_factory_reset(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ApiResponse<()>, String> {
    let storage_repo = LocalStorageRepo::new(&state.pool);
    let item_repo = LocalItemRepo::new(&state.pool);
    let vault_repo = LocalVaultRepo::new(&state.pool);
    let cursor_repo = SyncCursorRepo::new(&state.pool);
    let pending_repo = PendingChangeRepo::new(&state.pool);

    let storages = storage_repo.list().await.map_err(|e| e.to_string())?;

    for storage in &storages {
        let _ = pending_repo.delete_by_storage(storage.id).await;
        let _ = cursor_repo.delete_by_storage(&storage.id.to_string()).await;
        let _ = item_repo.delete_by_storage(storage.id).await;
        let _ = vault_repo.delete_by_storage(storage.id).await;
        let _ = storage_repo.delete(storage.id).await;
    }

    if let Ok(mut config) = load_config(&state.root) {
        config.contexts.clear();
        config.current_context = None;
        config.identity = None;
        let _ = save_config(&state.root, &config);
    }

    let settings_path = state.root.join(crate::constants::SETTINGS_FILENAME);
    let _ = std::fs::remove_file(&settings_path);

    let _ = app.biometry().remove_data(tauri_plugin_biometry::RemoveDataOptions {
        domain: crate::constants::BIOMETRY_DOMAIN.to_string(),
        name: crate::constants::BIOMETRY_NAME.to_string(),
    });

    {
        let mut mk = state.master_key.write().await;
        *mk = None;
    }

    Ok(ApiResponse::ok(()))
}

pub async fn app_version() -> Result<ApiResponse<AppVersionResponse>, String> {
    Ok(ApiResponse::ok(AppVersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: option_env!("GIT_HASH").map(|s| s.to_string()),
    }))
}

pub async fn open_data_folder(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ApiResponse<()>, String> {
    use tauri_plugin_shell::ShellExt;

    let data_path = &state.root;

    #[cfg(target_os = "macos")]
    let _ = app
        .shell()
        .command("open")
        .args([&data_path.display().to_string()])
        .spawn();

    #[cfg(target_os = "windows")]
    let _ = app
        .shell()
        .command("explorer")
        .args([&data_path.display().to_string()])
        .spawn();

    #[cfg(target_os = "linux")]
    let _ = app
        .shell()
        .command("xdg-open")
        .args([&data_path.display().to_string()])
        .spawn();

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let _ = &app;

    Ok(ApiResponse::ok(()))
}

pub async fn open_logs(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<ApiResponse<()>, String> {
    use tauri_plugin_shell::ShellExt;

    let logs_path = state.root.join("logs");
    let _ = std::fs::create_dir_all(&logs_path);

    #[cfg(target_os = "macos")]
    let _ = app
        .shell()
        .command("open")
        .args([&logs_path.display().to_string()])
        .spawn();

    #[cfg(target_os = "windows")]
    let _ = app
        .shell()
        .command("explorer")
        .args([&logs_path.display().to_string()])
        .spawn();

    #[cfg(target_os = "linux")]
    let _ = app
        .shell()
        .command("xdg-open")
        .args([&logs_path.display().to_string()])
        .spawn();

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    let _ = &app;

    Ok(ApiResponse::ok(()))
}
