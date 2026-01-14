use chrono::Utc;
use clap::Args;
use serde::Serialize;
use sqlx_core::query::query;
use sqlx_core::query_scalar::query_scalar;
use sqlx_postgres::Postgres;
use uuid::Uuid;
use zann_core::{CachePolicy, UserStatus, VaultEncryptionType, VaultKind, VaultMemberRole};
use zann_core::{Group, GroupMember, User, Vault, VaultMember};
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto;

use crate::config::AuthMode;
use crate::domains::auth::core::passwords::{
    derive_auth_hash, hash_password, random_kdf_salt, KdfParams,
};
use crate::infra::db::apply_tx_isolation;
use crate::settings::Settings;

#[derive(Debug, Clone, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub email: String,
    #[arg(long)]
    pub password: String,
    #[arg(long, value_name = "name")]
    pub vault_name: String,
    #[arg(long, value_name = "slug")]
    pub vault_slug: String,
}

#[derive(Debug, Serialize)]
struct InitOutput {
    user_id: String,
    user_email: String,
    vault_id: String,
    vault_slug: String,
    vault_name: String,
}

pub async fn run(settings: &Settings, db: &zann_db::PgPool, args: &InitArgs) -> Result<(), String> {
    if !settings.config.auth.internal.enabled || matches!(settings.config.auth.mode, AuthMode::Oidc)
    {
        return Err("internal_auth_disabled".to_string());
    }
    let Some(server_master_key) = settings.server_master_key.as_ref() else {
        return Err("server_master_key_missing".to_string());
    };

    let email = args.email.trim();
    let password = args.password.trim();
    let vault_name = args.vault_name.trim();
    let vault_slug = args.vault_slug.trim();
    if email.is_empty() {
        return Err("invalid_email".to_string());
    }
    if password.is_empty() {
        return Err("invalid_password".to_string());
    }
    if vault_name.is_empty() {
        return Err("invalid_vault_name".to_string());
    }
    if vault_slug.is_empty() {
        return Err("invalid_vault_slug".to_string());
    }

    let mut tx = db.begin().await.map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "DB begin failed");
        "db_error".to_string()
    })?;
    if let Err(err) = apply_tx_isolation(&mut tx, settings.db_tx_isolation).await {
        tracing::error!(event = "init_failed", error = %err, "DB isolation failed");
        return Err("db_error".to_string());
    }

    let existing_user = query::<Postgres>(
        r#"
        SELECT 1
        FROM users
        WHERE status != $1 AND deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(UserStatus::System as i32)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "User lookup failed");
        "db_error".to_string()
    })?;
    if existing_user.is_some() {
        if let Err(err) = tx.rollback().await {
            tracing::error!(event = "init_failed", error = %err, "DB rollback failed");
            return Err("db_error".to_string());
        }
        return Err("users_exist".to_string());
    }

    let email_exists = query::<Postgres>(
        r#"
        SELECT 1
        FROM users
        WHERE email = $1 AND deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Email lookup failed");
        "db_error".to_string()
    })?;
    if email_exists.is_some() {
        if let Err(err) = tx.rollback().await {
            tracing::error!(event = "init_failed", error = %err, "DB rollback failed");
            return Err("db_error".to_string());
        }
        return Err("email_exists".to_string());
    }

    let vault_exists = query::<Postgres>(
        r#"
        SELECT 1
        FROM vaults
        WHERE slug = $1 AND deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(vault_slug)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Vault lookup failed");
        "db_error".to_string()
    })?;
    if vault_exists.is_some() {
        if let Err(err) = tx.rollback().await {
            tracing::error!(event = "init_failed", error = %err, "DB rollback failed");
            return Err("db_error".to_string());
        }
        return Err("vault_slug_taken".to_string());
    }

    let params = KdfParams {
        algorithm: settings.config.auth.kdf.algorithm.clone(),
        iterations: settings.config.auth.kdf.iterations,
        memory_kb: settings.config.auth.kdf.memory_kb,
        parallelism: settings.config.auth.kdf.parallelism,
    };
    let kdf_salt = random_kdf_salt();
    let auth_hash = derive_auth_hash(password, &kdf_salt, &params).map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "KDF error");
        "kdf_error".to_string()
    })?;
    let password_hash =
        hash_password(&auth_hash, &settings.password_pepper, &params).map_err(|err| {
            tracing::error!(event = "init_failed", error = %err, "Password hash error");
            "kdf_error".to_string()
        })?;

    let now = Utc::now();
    let user = User {
        id: Uuid::now_v7(),
        email: email.to_string(),
        full_name: None,
        password_hash: Some(password_hash),
        recovery_key_hash: None,
        kdf_salt: kdf_salt.clone(),
        kdf_algorithm: params.algorithm.to_string(),
        kdf_iterations: i64::from(params.iterations),
        kdf_memory_kb: i64::from(params.memory_kb),
        kdf_parallelism: i64::from(params.parallelism),
        status: UserStatus::Active,
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
        updated_at: now,
        last_login_at: None,
    };

    query::<Postgres>(
        r#"
        INSERT INTO users (
            id,
            email,
            full_name,
            password_hash,
            kdf_salt,
            kdf_algorithm,
            kdf_iterations,
            kdf_memory_kb,
            kdf_parallelism,
            recovery_key_hash,
            status,
            deleted_at,
            deleted_by_user_id,
            deleted_by_device_id,
            row_version,
            created_at,
            updated_at,
            last_login_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
        )
        "#,
    )
    .bind(user.id)
    .bind(user.email.as_str())
    .bind(user.full_name.as_deref())
    .bind(user.password_hash.as_deref())
    .bind(user.kdf_salt.as_str())
    .bind(user.kdf_algorithm.as_str())
    .bind(user.kdf_iterations)
    .bind(user.kdf_memory_kb)
    .bind(user.kdf_parallelism)
    .bind(user.recovery_key_hash.as_deref())
    .bind(user.status as i32)
    .bind(user.deleted_at)
    .bind(user.deleted_by_user_id)
    .bind(user.deleted_by_device_id)
    .bind(user.row_version)
    .bind(user.created_at)
    .bind(user.updated_at)
    .bind(user.last_login_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "User create failed");
        "user_create_failed".to_string()
    })?;

    let admin_group_id = query_scalar::<Postgres, Uuid>(
        r#"
        SELECT id
        FROM groups
        WHERE slug = $1
        "#,
    )
    .bind("admins")
    .fetch_optional(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Group lookup failed");
        "db_error".to_string()
    })?
    .unwrap_or_else(Uuid::now_v7);

    let group = Group {
        id: admin_group_id,
        slug: "admins".to_string(),
        name: "Admins".to_string(),
        created_at: now,
    };

    query::<Postgres>(
        r#"
        INSERT INTO groups (id, slug, name, created_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (slug) DO NOTHING
        "#,
    )
    .bind(group.id)
    .bind(group.slug.as_str())
    .bind(group.name.as_str())
    .bind(group.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Group create failed");
        "group_create_failed".to_string()
    })?;

    let group_member = GroupMember {
        group_id: group.id,
        user_id: user.id,
        created_at: now,
    };
    query::<Postgres>(
        r#"
        INSERT INTO group_members (group_id, user_id, created_at)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(group_member.group_id)
    .bind(group_member.user_id)
    .bind(group_member.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Group member create failed");
        "group_member_create_failed".to_string()
    })?;

    let vault_id = Uuid::now_v7();
    let vault_key = SecretKey::generate();
    let vault_key_enc = vault_crypto::encrypt_vault_key(server_master_key, vault_id, &vault_key)
        .map_err(|err| {
            tracing::error!(event = "init_failed", error = %err, "Vault key encrypt failed");
            "vault_key_encrypt_failed".to_string()
        })?;

    let vault = Vault {
        id: vault_id,
        slug: vault_slug.to_string(),
        name: vault_name.to_string(),
        kind: VaultKind::Shared,
        encryption_type: VaultEncryptionType::Server,
        vault_key_enc: vault_key_enc.clone(),
        cache_policy: CachePolicy::Full,
        tags: Some(sqlx_core::types::Json(Vec::<String>::new())),
        deleted_at: None,
        deleted_by_user_id: None,
        deleted_by_device_id: None,
        row_version: 1,
        created_at: now,
    };

    query::<Postgres>(
        r#"
        INSERT INTO vaults (
            id, slug, name, kind, encryption_type, vault_key_enc, cache_policy, tags,
            deleted_at, deleted_by_user_id, deleted_by_device_id, row_version, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(vault.id)
    .bind(vault.slug.as_str())
    .bind(vault.name.as_str())
    .bind(VaultKind::Shared.as_i32())
    .bind(VaultEncryptionType::Server.as_i32())
    .bind(&vault.vault_key_enc)
    .bind(CachePolicy::Full as i32)
    .bind(&vault.tags)
    .bind(vault.deleted_at)
    .bind(vault.deleted_by_user_id)
    .bind(vault.deleted_by_device_id)
    .bind(vault.row_version)
    .bind(vault.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Vault create failed");
        "vault_create_failed".to_string()
    })?;

    let member = VaultMember {
        vault_id: vault.id,
        user_id: user.id,
        role: VaultMemberRole::Admin,
        created_at: now,
    };
    query::<Postgres>(
        r#"
        INSERT INTO vault_members (vault_id, user_id, role, created_at)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(member.vault_id)
    .bind(member.user_id)
    .bind(member.role as i32)
    .bind(member.created_at)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "Vault member create failed");
        "vault_member_create_failed".to_string()
    })?;

    tx.commit().await.map_err(|err| {
        tracing::error!(event = "init_failed", error = %err, "DB commit failed");
        "db_error".to_string()
    })?;

    let output = InitOutput {
        user_id: user.id.to_string(),
        user_email: user.email,
        vault_id: vault.id.to_string(),
        vault_slug: vault.slug,
        vault_name: vault.name,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| {
            tracing::error!(event = "init_output_failed", error = %err);
            err.to_string()
        })?
    );
    Ok(())
}
