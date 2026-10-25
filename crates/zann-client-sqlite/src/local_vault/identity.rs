use super::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct IdentityConfig {
    pub(super) kdf_salt: String,
    pub(super) kdf_params: zann_core::api::auth::KdfParams,
    #[serde(default)]
    pub(super) salt_fingerprint: Option<String>,
    #[serde(default)]
    pub(super) first_seen_at: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
}

pub(super) fn load_or_create_identity_config(root: &Path) -> LocalResult<IdentityConfig> {
    let path = root.join("config.json");
    let mut config = match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str::<Value>(&contents).map_err(|err| {
            LocalError::Service(format!(
                "failed to parse config.json at {}: {}",
                path.display(),
                err
            ))
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Value::Object(serde_json::Map::new())
        }
        Err(err) => return Err(LocalError::Service(err.to_string())),
    };

    let identity = config
        .get("identity")
        .and_then(|value| serde_json::from_value::<IdentityConfig>(value.clone()).ok());
    if let Some(identity) = identity {
        return Ok(identity);
    }

    crate::maintenance::secure_file::ensure_private_dir(root)
        .map_err(|err| LocalError::Service(err.to_string()))?;
    let salt = SecretKey::generate();
    let salt_b64 = base64::engine::general_purpose::STANDARD.encode(salt.as_bytes());
    let identity = IdentityConfig {
        kdf_salt: salt_b64,
        kdf_params: default_local_kdf_params(),
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    };
    let identity_value =
        serde_json::to_value(&identity).map_err(|err| LocalError::Service(err.to_string()))?;
    if let Value::Object(map) = &mut config {
        map.insert("identity".to_string(), identity_value);
    } else {
        config = serde_json::json!({ "identity": identity_value });
    }
    let json = serde_json::to_string_pretty(&config)
        .map_err(|err| LocalError::Service(err.to_string()))?;
    crate::maintenance::secure_file::write_private(&path, json.as_bytes())
        .map_err(|err| LocalError::Service(err.to_string()))?;
    Ok(identity)
}

pub(super) fn derive_master_key(
    password: &str,
    identity: &IdentityConfig,
) -> LocalResult<SecretKey> {
    let params = identity.kdf_params.to_crypto_params();
    let key = zann_core::passwords::derive_auth_hash(password, &identity.kdf_salt, &params)
        .map_err(|err| LocalError::InvalidArgument(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
}

pub(super) fn default_local_kdf_params() -> zann_core::api::auth::KdfParams {
    zann_core::api::auth::KdfParams {
        algorithm: "argon2id".to_string(),
        iterations: 3,
        memory_kb: 65536,
        parallelism: 4,
    }
}

pub(super) fn resolve_storage_id(runtime: &Runtime, pool: &SqlitePool) -> LocalResult<Uuid> {
    let repo = LocalStorageRepo::new(pool);
    let vault_repo = LocalVaultRepo::new(pool);
    let item_repo = LocalItemRepo::new(pool);
    let storages = runtime
        .block_on(repo.list())
        .map_err(|err| LocalError::Service(err.to_string()))?;
    if storages.is_empty() {
        return Ok(Uuid::nil());
    }

    let mut selected = (storages[0].id, 0usize);
    for storage in &storages {
        let vaults = runtime
            .block_on(vault_repo.list_by_storage(storage.id))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        let mut total = 0usize;
        for vault in vaults {
            let count = runtime
                .block_on(item_repo.count_by_vault(storage.id, vault.id))
                .map_err(|err| LocalError::Service(err.to_string()))?;
            total = total.saturating_add(count as usize);
        }
        if total > selected.1 {
            selected = (storage.id, total);
        }
    }

    if selected.1 == 0 {
        if let Some(local) = storages
            .iter()
            .find(|storage| storage.kind == zann_core::StorageKind::LocalOnly)
        {
            return Ok(local.id);
        }
    }

    Ok(selected.0)
}
