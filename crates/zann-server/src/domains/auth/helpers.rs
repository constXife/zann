use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_postgres::{PgConnection, Postgres};
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

    if let Err(err) = vault_repo.create(&vault).await {
        if vault_repo
            .get_personal_by_user(user_id)
            .await
            .map_err(|_| "db_error")?
            .is_some()
        {
            return Ok(());
        }
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            "DB error"
        );
        return Err("db_error");
    }

    let member_repo = VaultMemberRepo::new(&state.db);
    let member = VaultMember {
        vault_id: vault.id,
        user_id,
        role: VaultMemberRole::Admin,
        created_at: now,
    };
    if let Err(err) = member_repo.create(&member).await {
        if member_repo
            .get(vault.id, user_id)
            .await
            .map_err(|_| "db_error")?
            .is_some()
        {
            return Ok(());
        }
        tracing::error!(
            event = "personal_vault_member_create_failed",
            error = %err,
            "DB error"
        );
        return Err("db_error");
    }

    Ok(())
}

pub(crate) async fn ensure_personal_vault_tx(
    state: &AppState,
    conn: &mut PgConnection,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if !state.config.server.personal_vaults_enabled {
        return Ok(());
    }

    let existing = query::<Postgres>(
        r#"
        SELECT v.id
        FROM vaults v
        INNER JOIN vault_members vm ON vm.vault_id = v.id
        WHERE vm.user_id = $1 AND v.kind = $2 AND v.deleted_at IS NULL
        ORDER BY v.created_at ASC
        LIMIT 1
        "#,
    )
    .bind(user_id)
    .bind(VaultKind::Personal.as_i32())
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| "db_error")?;
    if existing.is_some() {
        return Ok(());
    }

    let vault_id = Uuid::now_v7();
    let tags = sqlx_core::types::Json(Vec::<String>::new());
    if let Err(err) = query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, tags,
            deleted_at, deleted_by_user_id, deleted_by_device_id, row_version, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(vault_id)
    .bind(format!("personal-{}", user_id))
    .bind("Personal")
    .bind(VaultKind::Personal.as_i32())
    .bind(VaultEncryptionType::Client.as_i32())
    .bind(Vec::<u8>::new())
    .bind(CachePolicy::Full.as_i32())
    .bind(&tags)
    .bind(None::<DateTime<Utc>>)
    .bind(None::<Uuid>)
    .bind(None::<Uuid>)
    .bind(1_i64)
    .bind(now)
    .execute(&mut *conn)
    .await
    {
        let existing = query::<Postgres>(
            r#"
            SELECT v.id
            FROM vaults v
            INNER JOIN vault_members vm ON vm.vault_id = v.id
            WHERE vm.user_id = $1 AND v.kind = 1 AND v.deleted_at IS NULL
            ORDER BY v.created_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| "db_error")?;
        if existing.is_some() {
            return Ok(());
        }
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            "DB error"
        );
        return Err("db_error");
    }

    if let Err(err) = query::<Postgres>(
        r#"
        INSERT INTO vault_members (vault_id, user_id, role, created_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(vault_id)
    .bind(user_id)
    .bind(VaultMemberRole::Admin.as_i32())
    .bind(now)
    .execute(&mut *conn)
    .await
    {
        let existing = query::<Postgres>(
            r#"
            SELECT 1
            FROM vault_members
            WHERE vault_id = $1 AND user_id = $2
            "#,
        )
        .bind(vault_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|_| "db_error")?;
        if existing.is_some() {
            return Ok(());
        }
        tracing::error!(
            event = "personal_vault_member_create_failed",
            error = %err,
            "DB error"
        );
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
