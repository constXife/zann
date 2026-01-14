use chrono::{DateTime, Utc};
use sqlx_core::query::query;
use sqlx_postgres::{PgConnection, Postgres};
use uuid::Uuid;
use zann_core::{CachePolicy, Device, Session, VaultEncryptionType, VaultKind, VaultMemberRole};

use crate::app::AppState;
use crate::domains::auth::core::tokens::hash_token;
use crate::infra::db::apply_tx_isolation;
use zann_core::api::auth::LoginResponse;

pub(crate) async fn ensure_personal_vault(
    state: &AppState,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    if !state.config.server.personal_vaults_enabled {
        return Ok(());
    }

    let mut tx = state.db.begin().await.map_err(|err| {
        tracing::error!(event = "personal_vault_create_failed", error = %err, "DB begin failed");
        "db_error"
    })?;
    if let Err(err) = apply_tx_isolation(&mut tx, state.db_tx_isolation).await {
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            "DB isolation failed"
        );
        return Err("db_error");
    }

    ensure_personal_vault_tx(state, &mut tx, user_id, now).await?;

    tx.commit().await.map_err(|err| {
        tracing::error!(
            event = "personal_vault_create_failed",
            error = %err,
            "DB commit failed"
        );
        "db_error"
    })?;

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

    if let Err(err) = query::<Postgres>("SELECT pg_advisory_xact_lock(hashtext($1)::bigint)")
        .bind(user_id.to_string())
        .execute(&mut *conn)
        .await
    {
        tracing::error!(
            event = "personal_vault_lock_failed",
            error = %err,
            "DB error"
        );
        return Err("db_error");
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

pub(crate) struct SessionTokens {
    pub(crate) session: Session,
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
}

pub(crate) fn create_session_for_user(
    state: &AppState,
    user_id: Uuid,
    device_id: Uuid,
    now: DateTime<Utc>,
) -> SessionTokens {
    let refresh_token = Uuid::now_v7().to_string();
    let access_token = Uuid::now_v7().to_string();
    let refresh_token_hash = hash_token(&refresh_token, &state.token_pepper);
    let access_token_hash = hash_token(&access_token, &state.token_pepper);
    let access_expires_at = now + chrono::Duration::seconds(state.access_token_ttl_seconds);

    let session = Session {
        id: Uuid::now_v7(),
        user_id,
        device_id,
        access_token_hash,
        access_expires_at,
        refresh_token_hash,
        expires_at: now + chrono::Duration::seconds(state.refresh_token_ttl_seconds),
        created_at: now,
    };

    SessionTokens {
        session,
        access_token,
        refresh_token,
    }
}

pub(crate) fn build_login_response(
    state: &AppState,
    access_token: String,
    refresh_token: String,
) -> LoginResponse {
    LoginResponse {
        access_token,
        refresh_token,
        expires_in: ttl_seconds_u64(state.access_token_ttl_seconds),
    }
}

pub(crate) fn ttl_seconds_u64(ttl_seconds: i64) -> u64 {
    u64::try_from(ttl_seconds).unwrap_or(0)
}
