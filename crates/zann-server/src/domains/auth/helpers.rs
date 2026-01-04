use chrono::{DateTime, Utc};
use uuid::Uuid;
use zann_core::{
    CachePolicy, Device, Vault, VaultEncryptionType, VaultKind, VaultMember, VaultMemberRole,
};
use zann_db::repo::{VaultMemberRepo, VaultRepo};

use crate::app::AppState;

pub(crate) async fn ensure_personal_vault(
    state: &AppState,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if !state.config.server.personal_vaults_enabled {
        return Ok(());
    }

    let vault_repo = VaultRepo::new(&state.db);
    if vault_repo
        .get_personal_by_user(user_id)
        .await
        .map_err(|_| "db_error")?
        .is_some()
    {
        return Ok(());
    }

    let vault_id = Uuid::now_v7();
    let vault = Vault {
        id: vault_id,
        slug: format!("personal-{}", user_id),
        name: "Personal".to_string(),
        kind: VaultKind::Personal,
        encryption_type: VaultEncryptionType::Client,
        vault_key_enc: Vec::new(),
        cache_policy: CachePolicy::Full,
        tags: None,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
    };

    if vault_repo.create(&vault).await.is_err() {
        if vault_repo
            .get_personal_by_user(user_id)
            .await
            .map_err(|_| "db_error")?
            .is_some()
        {
            return Ok(());
        }
        return Err("db_error");
    }

    let member_repo = VaultMemberRepo::new(&state.db);
    let member = VaultMember {
        vault_id: vault.id,
        user_id,
        role: VaultMemberRole::Admin,
        created_at: now,
    };
    if member_repo.create(&member).await.is_err() {
        if member_repo
            .get(vault.id, user_id)
            .await
            .map_err(|_| "db_error")?
            .is_some()
        {
            return Ok(());
        }
        return Err("db_error");
    }

    Ok(())
}

pub(crate) fn build_device(
    user_id: Uuid,
    name: Option<String>,
    platform: Option<String>,
    fingerprint: Option<String>,
    os: Option<String>,
    os_version: Option<String>,
    app_version: Option<String>,
    default_name: &str,
    default_os: &str,
    now: DateTime<Utc>,
) -> Device {
    let os_value = os.or(platform).unwrap_or_else(|| default_os.to_string());
    Device {
        id: Uuid::now_v7(),
        user_id,
        name: name.unwrap_or_else(|| default_name.to_string()),
        fingerprint: fingerprint.unwrap_or_else(|| "unknown".to_string()),
        os: Some(os_value),
        os_version,
        app_version,
        last_seen_at: None,
        last_ip: None,
        revoked_at: None,
        created_at: now,
    }
}
