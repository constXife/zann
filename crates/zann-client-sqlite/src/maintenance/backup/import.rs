use super::*;

pub async fn plain_import(
    ctx: &BackupCtx,
    path: PathBuf,
    target_storage_id: Option<String>,
) -> Result<ImportOutcome, BackupError> {
    ctx.log(&format!(
        "import_mode_raw target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
    let target_storage_id = match target_storage_id.as_deref() {
        Some("local") | Some("") => None,
        other => other.map(str::to_string),
    };
    ctx.log(&format!(
        "import_mode_select target_storage_id={}",
        target_storage_id.as_deref().unwrap_or("<none>")
    ));
    let master_key = ctx.master_key.clone();
    let services = LocalServices::new(&ctx.pool, master_key.as_ref());
    let storage_repo = LocalStorageRepo::new(&ctx.pool);
    let vault_repo = LocalVaultRepo::new(&ctx.pool);
    let item_repo = LocalItemRepo::new(&ctx.pool);

    let mut target_storage_id = target_storage_id;
    if target_storage_id.is_none() {
        if let Ok(storages) = storage_repo.list().await {
            let remote = storages
                .into_iter()
                .filter(|storage| storage.kind == StorageKind::Remote)
                .collect::<Vec<_>>();
            if remote.len() == 1 {
                target_storage_id = Some(remote[0].id.to_string());
                ctx.log(&format!("import_mode_fallback storage_id={}", remote[0].id));
            }
        }
    }

    if let Some(target_storage_id) = target_storage_id.as_deref() {
        let target_id =
            Uuid::parse_str(target_storage_id).map_err(|_| "invalid storage id".to_string())?;
        match storage_repo.get(target_id).await {
            Ok(Some(storage)) => {
                ctx.log(&format!(
                    "import_mode_candidate storage_id={} kind={}",
                    storage.id,
                    storage.kind.as_i32()
                ));
                if storage.kind == StorageKind::Remote {
                    ctx.log(&format!("import_mode_remote storage_id={}", storage.id));
                    return Ok(ImportOutcome::NeedsRemote(storage));
                }
                ctx.log("import_mode_fallback reason=storage_not_remote");
            }
            Ok(None) => {
                ctx.log("import_mode_fallback reason=storage_not_found");
            }
            Err(err) => {
                ctx.log(&format!(
                    "import_mode_fallback reason=storage_lookup_failed error={}",
                    err
                ));
            }
        }
    }

    let input_path = path;
    ctx.log(&format!("import_start path={}", input_path.display()));
    ctx.log(&format!("import_read_start path={}", input_path.display()));
    let backup_meta = match read_backup_metadata(&input_path) {
        Ok(meta) => meta,
        Err(err) => {
            ctx.log(&format!(
                "import_failed path={} error={}",
                input_path.display(),
                err
            ));
            return Err(err.to_string().into());
        }
    };
    ctx.log(&format!(
        "import_read_ok path={} storages={} vaults={} items=streaming",
        input_path.display(),
        backup_meta.storages.len(),
        backup_meta.vaults.len()
    ));
    if backup_meta.version != BACKUP_VERSION {
        ctx.log(&format!(
            "import_failed path={} error=unsupported_version version={}",
            input_path.display(),
            backup_meta.version
        ));
        return Err(BackupError::new(
            "backup_version_unsupported",
            "unsupported backup version",
        ));
    }

    let mut storage_map: HashMap<Uuid, Uuid> = HashMap::new();
    let local_storage_id = Uuid::nil();
    let log_error = |message: &str| {
        ctx.log(&format!(
            "import_failed path={} error={}",
            input_path.display(),
            message
        ));
        message.to_string()
    };
    let mut created_storages = 0usize;
    let mut mapped_to_local = 0usize;
    for storage in backup_meta.storages {
        let storage_id =
            Uuid::parse_str(&storage.id).map_err(|_| log_error("invalid storage id"))?;
        let kind =
            StorageKind::try_from(storage.kind).map_err(|_| log_error("invalid storage kind"))?;
        let existing = storage_repo
            .get(storage_id)
            .await
            .map_err(|err| log_error(&err.to_string()))?;
        if let Some(existing) = existing {
            storage_map.insert(storage_id, existing.id);
            continue;
        }
        if kind == StorageKind::LocalOnly {
            let local_storage = LocalStorage {
                id: storage_id,
                kind,
                name: storage.name,
                server_url: storage.server_url,
                server_name: storage.server_name,
                server_fingerprint: storage.server_fingerprint,
                account_subject: storage.account_subject,
                personal_vaults_enabled: storage.personal_vaults_enabled,
                auth_method: storage
                    .auth_method
                    .map(AuthMethod::try_from)
                    .transpose()
                    .map_err(|_| "invalid auth method")?,
            };
            storage_repo
                .upsert(&local_storage)
                .await
                .map_err(|err| log_error(&err.to_string()))?;
            storage_map.insert(storage_id, storage_id);
            created_storages += 1;
        } else {
            storage_map.insert(storage_id, local_storage_id);
            mapped_to_local += 1;
            ctx.log(&format!(
                "import_storage_mapped path={} storage_id={} mapped_to={}",
                input_path.display(),
                storage_id,
                local_storage_id
            ));
        }
    }
    ctx.log(&format!(
        "import_storages_done path={} total={} created={} mapped_to_local={}",
        input_path.display(),
        storage_map.len(),
        created_storages,
        mapped_to_local
    ));

    let mut vault_map: HashMap<(Uuid, Uuid), (Uuid, Uuid)> = HashMap::new();
    let mut created_vaults = 0usize;
    let mut reused_vaults = 0usize;
    for vault in &backup_meta.vaults {
        let backup_storage_id =
            Uuid::parse_str(&vault.storage_id).map_err(|_| log_error("invalid storage id"))?;
        let backup_vault_id =
            Uuid::parse_str(&vault.id).map_err(|_| log_error("invalid vault id"))?;
        let Some(&target_storage_id) = storage_map.get(&backup_storage_id) else {
            ctx.log(&format!(
                "import_vault_skip path={} storage_id={} vault_id={} reason=missing_storage",
                input_path.display(),
                backup_storage_id,
                backup_vault_id
            ));
            continue;
        };
        if let Some(existing) = vault_repo
            .get_by_name(target_storage_id, &vault.name)
            .await
            .map_err(|err| log_error(&err.to_string()))?
        {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                (target_storage_id, existing.id),
            );
            reused_vaults += 1;
            ctx.log(&format!(
                "import_vault_reuse path={} storage_id={} vault_id={} existing_vault_id={} name={}",
                input_path.display(),
                backup_storage_id,
                backup_vault_id,
                existing.id,
                vault.name
            ));
            continue;
        }
        if let Some(existing) = vault_repo
            .get_by_id(target_storage_id, backup_vault_id)
            .await
            .map_err(|err| log_error(&err.to_string()))?
        {
            vault_map.insert(
                (backup_storage_id, backup_vault_id),
                (target_storage_id, existing.id),
            );
            reused_vaults += 1;
            ctx.log(&format!(
                "import_vault_reuse path={} storage_id={} vault_id={} existing_vault_id={} reason=id_match",
                input_path.display(),
                backup_storage_id,
                backup_vault_id,
                existing.id
            ));
            continue;
        }

        let vault_kind =
            VaultKind::try_from(vault.kind).map_err(|_| log_error("invalid vault kind"))?;
        let vault_id_to_use = if target_storage_id == backup_storage_id {
            backup_vault_id
        } else {
            Uuid::now_v7()
        };
        let vault_key = SecretKey::generate();
        let vault_key_enc =
            core_crypto::encrypt_vault_key(master_key.as_ref(), vault_id_to_use, &vault_key)
                .map_err(|err| log_error(&err.to_string()))?;
        let base_name = vault.name.clone();
        let mut created = false;
        for attempt in 0..6 {
            let name = if attempt == 0 {
                base_name.clone()
            } else {
                format!("{base_name} (import {attempt})")
            };
            let local_vault = LocalVault {
                id: vault_id_to_use,
                storage_id: target_storage_id,
                slug: LocalVault::local_slug(vault_id_to_use),
                name: name.clone(),
                kind: vault_kind,
                is_default: vault.is_default,
                vault_key_enc: vault_key_enc.clone(),
                key_wrap_type: KeyWrapType::Master,
                cache_key_fp: None,
                last_synced_at: None,
            };
            match vault_repo.create(&local_vault).await {
                Ok(()) => {
                    if attempt > 0 {
                        ctx.log(&format!(
                            "import_vault_renamed path={} storage_id={} vault_id={} name_from={} name_to={}",
                            input_path.display(),
                            target_storage_id,
                            vault_id_to_use,
                            base_name,
                            name
                        ));
                    }
                    vault_map.insert(
                        (backup_storage_id, backup_vault_id),
                        (target_storage_id, vault_id_to_use),
                    );
                    created_vaults += 1;
                    created = true;
                    break;
                }
                Err(err) => {
                    let message = err.to_string();
                    if message.contains(
                        "UNIQUE constraint failed: local_vaults.storage_id, local_vaults.name",
                    ) {
                        continue;
                    }
                    return Err(log_error(&message).into());
                }
            }
        }
        if !created {
            return Err(log_error("vault_name_conflict").into());
        }
    }
    ctx.log(&format!(
        "import_vaults_done path={} total={} created={} reused={}",
        input_path.display(),
        vault_map.len(),
        created_vaults,
        reused_vaults
    ));

    ctx.log(&format!(
        "import_items_start path={} total=streaming",
        input_path.display()
    ));
    #[derive(Default)]
    struct ImportCounters {
        imported_items: usize,
        skipped_existing: usize,
        skipped_missing_storage: usize,
        skipped_missing_vault: usize,
        skipped_deleted: usize,
    }

    let counters = Arc::new(Mutex::new(ImportCounters::default()));
    let api_error = Arc::new(Mutex::new(None));
    let path_display = input_path.display().to_string();
    let storage_map_ref = &storage_map;
    let vault_map_ref = &vault_map;
    let services_ref = &services;
    let item_repo_ref = &item_repo;

    let stream_result = stream_backup_items_async(&input_path, |item, index| {
        let counters = Arc::clone(&counters);
        let api_error = Arc::clone(&api_error);
        let path_display = path_display.clone();
        async move {
            ctx.log(&format!(
                "import_item_start path={} index={} item_id={}",
                path_display,
                index,
                item.id.as_deref().unwrap_or("new")
            ));
            if item.deleted_at.is_some() {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_deleted += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=deleted",
                    path_display, index
                ));
                return Ok(());
            }
            let backup_storage_id =
                Uuid::parse_str(&item.storage_id).map_err(|_| "invalid storage id".to_string())?;
            let backup_vault_id =
                Uuid::parse_str(&item.vault_id).map_err(|_| "invalid vault id".to_string())?;
            if !storage_map_ref.contains_key(&backup_storage_id) {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_storage += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=missing_storage",
                    path_display, index
                ));
                return Ok(());
            }
            let Some(&(target_storage_id, target_vault_id)) =
                vault_map_ref.get(&(backup_storage_id, backup_vault_id))
            else {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_missing_vault += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=missing_vault",
                    path_display, index
                ));
                return Ok(());
            };
            let existing = item_repo_ref
                .get_active_by_vault_path(target_storage_id, target_vault_id, &item.path)
                .await
                .map_err(|err| err.to_string())?;
            if existing.is_some() {
                let mut guard = counters
                    .lock()
                    .map_err(|_| "counter_lock_failed".to_string())?;
                guard.skipped_existing += 1;
                ctx.log(&format!(
                    "import_item_skip path={} index={} reason=existing_path",
                    path_display, index
                ));
                return Ok(());
            }
            match services_ref
                .put_item(
                    target_storage_id,
                    target_vault_id,
                    item.path.clone(),
                    item.type_id.clone(),
                    item.payload.clone(),
                )
                .await
            {
                Ok(_) => {
                    let mut guard = counters
                        .lock()
                        .map_err(|_| "counter_lock_failed".to_string())?;
                    guard.imported_items += 1;
                    ctx.log(&format!(
                        "import_item_ok path={} index={}",
                        path_display, index
                    ));
                }
                Err(err) if err.kind == "item_exists" => {
                    let mut guard = counters
                        .lock()
                        .map_err(|_| "counter_lock_failed".to_string())?;
                    guard.skipped_existing += 1;
                    ctx.log(&format!(
                        "import_item_skip path={} index={} reason=item_exists",
                        path_display, index
                    ));
                }
                Err(err) => {
                    ctx.log(&format!(
                        "import_failed path={} error={}",
                        path_display, err.message
                    ));
                    if let Ok(mut guard) = api_error.lock() {
                        *guard = Some((err.kind, err.message));
                    }
                    return Err("import_failed".to_string());
                }
            }
            Ok(())
        }
    })
    .await;
    if let Ok(guard) = api_error.lock() {
        if let Some((kind, message)) = guard.as_ref() {
            return Err(BackupError::new(kind.clone(), message.clone()));
        }
    }
    if let Err(err) = stream_result {
        ctx.log(&format!(
            "import_failed path={} error={}",
            input_path.display(),
            err
        ));
        return Err(err.into());
    }

    let counters = counters
        .lock()
        .map_err(|_| "counter_lock_failed".to_string())?;
    let imported_items = counters.imported_items;
    let skipped_existing = counters.skipped_existing;
    let skipped_missing_storage = counters.skipped_missing_storage;
    let skipped_missing_vault = counters.skipped_missing_vault;
    let skipped_deleted = counters.skipped_deleted;

    ctx.log(&format!(
        "import_ok path={} imported={} skipped_existing={} skipped_missing_storage={} skipped_missing_vault={} skipped_deleted={}",
        input_path.display(),
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted
    ));
    Ok(ImportOutcome::Done(ImportReport {
        imported_items,
        skipped_existing,
        skipped_missing_storage,
        skipped_missing_vault,
        skipped_deleted,
    }))
}
