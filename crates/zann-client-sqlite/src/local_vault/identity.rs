use super::*;

/// A fresh identity for a vault that is local-only from the start. A vault
/// that came from a server never gets one: its identity is the account's,
/// committed by the login.
pub(super) fn new_local_identity() -> ConfigIdentity {
    let salt = SecretKey::generate();
    ConfigIdentity {
        kdf_salt: base64::engine::general_purpose::STANDARD.encode(salt.as_bytes()),
        kdf_params: ConfigKdfParams {
            algorithm: "argon2id".to_string(),
            iterations: 3,
            memory_kb: 65536,
            parallelism: 4,
        },
        salt_fingerprint: None,
        first_seen_at: None,
        email: None,
    }
}

pub(super) fn derive_master_key(
    password: &str,
    identity: &ConfigIdentity,
) -> LocalResult<SecretKey> {
    let params =
        zann_core::api::auth::KdfParams::from(identity.kdf_params.clone()).to_crypto_params();
    let key = zann_core::passwords::derive_auth_hash(password, &identity.kdf_salt, &params)
        .map_err(|err| LocalError::InvalidArgument(err.to_string()))?;
    Ok(SecretKey::from_bytes(key))
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
