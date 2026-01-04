use chrono::Utc;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use zann_core::{ServiceAccount, VaultEncryptionType};
use zann_db::repo::{ServiceAccountRepo, ServiceAccountSessionRepo};

use crate::domains::auth::core::passwords;
use crate::settings;
use std::fs;

use super::models::{
    normalize_prefix, parse_ops, parse_scope_entry, parse_token_payload, parse_ttl, resolve_owner,
    resolve_shared_vault, scope_entries_match_encryption, scope_entries_shared, ScopeEntry,
    TokenDescription,
};
use super::{tokens_usage, SERVICE_ACCOUNT_PREFIX, SERVICE_ACCOUNT_PREFIX_LEN, SYSTEM_OWNER_EMAIL};

pub(super) async fn tokens_create(
    settings: &settings::Settings,
    db: &zann_db::PgPool,
    mut args: impl Iterator<Item = String>,
) -> Result<(), String> {
    let mut name: Option<String> = None;
    let mut vault_selector: Option<String> = None;
    let mut prefixes: Vec<String> = Vec::new();
    let mut ops: Option<String> = None;
    let mut ttl: Option<String> = None;
    let mut owner_email: Option<String> = None;
    let mut owner_id: Option<String> = None;
    let mut issued_by_email: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = args.next(),
            "--vault" => vault_selector = args.next(),
            "--prefix" => {
                let value = args
                    .next()
                    .ok_or_else(|| tokens_usage("missing --prefix"))?;
                prefixes.push(value);
            }
            "--ops" => ops = args.next(),
            "--ttl" => ttl = args.next(),
            "--owner-email" => owner_email = args.next(),
            "--owner-id" => owner_id = args.next(),
            "--issued-by-email" => issued_by_email = args.next(),
            _ => return Err(tokens_usage(&format!("unknown arg: {arg}"))),
        }
    }

    let name = name.ok_or_else(|| tokens_usage("missing --name"))?;
    let vault_selector = vault_selector.ok_or_else(|| tokens_usage("missing --vault"))?;
    if prefixes.is_empty() {
        return Err(tokens_usage("missing --prefix"));
    }
    let issued_by_email =
        issued_by_email.ok_or_else(|| tokens_usage("missing --issued-by-email"))?;
    if issued_by_email.trim().is_empty() {
        return Err(tokens_usage("invalid --issued-by-email"));
    }
    if owner_email.is_none() && owner_id.is_none() {
        owner_email = Some(SYSTEM_OWNER_EMAIL.to_string());
    }
    let owner = resolve_owner(db, owner_email.as_deref(), owner_id.as_deref()).await?;
    let ops = ops.unwrap_or_else(|| "read".to_string());
    let permissions = parse_ops(&ops)?;
    let expires_at = ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()?
        .map(|duration| Utc::now() + duration);

    let vault = resolve_shared_vault(db, &vault_selector).await?;
    let mut normalized_prefixes = Vec::new();
    let mut full_vault = false;
    for prefix in prefixes {
        if prefix.trim() == "/" {
            full_vault = true;
            continue;
        }
        normalized_prefixes.push(normalize_prefix(&prefix)?);
    }
    if full_vault && !normalized_prefixes.is_empty() {
        return Err("prefix '/' cannot be combined with other prefixes".to_string());
    }
    if !full_vault && normalized_prefixes.is_empty() {
        return Err(tokens_usage("missing --prefix"));
    }

    let scopes: Vec<String> = if full_vault {
        permissions
            .iter()
            .map(|permission| format!("{}:{permission}", vault.id))
            .collect()
    } else {
        normalized_prefixes
            .iter()
            .flat_map(|normalized_prefix| {
                permissions.iter().map(|permission| {
                    format!(
                        "{}/prefix:{}:{}",
                        vault.id, normalized_prefix.scope, permission
                    )
                })
            })
            .collect()
    };

    let token_suffix: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let token = format!("{SERVICE_ACCOUNT_PREFIX}{token_suffix}");
    let token_prefix: String = token.chars().take(SERVICE_ACCOUNT_PREFIX_LEN).collect();
    let params = passwords::KdfParams {
        algorithm: settings.config.auth.kdf.algorithm.clone(),
        iterations: settings.config.auth.kdf.iterations,
        memory_kb: settings.config.auth.kdf.memory_kb,
        parallelism: settings.config.auth.kdf.parallelism,
    };
    let token_hash = passwords::hash_service_token(&token, &settings.token_pepper, &params)
        .map_err(|_| "token_hash_failed".to_string())?;

    let now = Utc::now();
    let prefixes_display: Vec<String> = if full_vault {
        vec!["/".to_string()]
    } else {
        normalized_prefixes
            .iter()
            .map(|value| value.canonical.clone())
            .collect()
    };
    let token_description = TokenDescription {
        issued_by: issued_by_email,
        vault_id: vault.id.to_string(),
        vault_slug: vault.slug.clone(),
        prefix: prefixes_display.first().cloned(),
        prefixes: Some(prefixes_display.clone()),
        ops: permissions
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    };
    let description = Some(
        serde_json::to_string(&token_description)
            .map_err(|_| "description_encode_failed".to_string())?,
    );
    let account = ServiceAccount {
        id: uuid::Uuid::now_v7(),
        owner_user_id: owner,
        name,
        description,
        token_hash,
        token_prefix,
        scopes: sqlx_core::types::Json(scopes),
        allowed_ips: None,
        expires_at,
        last_used_at: None,
        last_used_ip: None,
        last_used_user_agent: None,
        use_count: 0,
        created_at: now,
        revoked_at: None,
    };

    let repo = ServiceAccountRepo::new(db);
    repo.create(&account)
        .await
        .map_err(|_| "service_account_create_failed".to_string())?;

    let output = serde_json::json!({
        "token": token,
        "service_account": {
            "id": account.id,
            "owner_user_id": account.owner_user_id,
            "name": account.name,
            "token_prefix": account.token_prefix,
            "scopes": account.scopes.0,
            "issued_by": token_description.issued_by,
            "vault_id": token_description.vault_id,
            "vault_slug": token_description.vault_slug,
            "prefix": token_description.prefix,
            "prefixes": token_description.prefixes,
            "ops": token_description.ops,
            "expires_at": account.expires_at.map(|dt| dt.to_rfc3339()),
            "created_at": account.created_at.to_rfc3339(),
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn tokens_create_or_rotate(
    settings: &settings::Settings,
    db: &zann_db::PgPool,
    args: &[String],
    rotate: bool,
) -> Result<(), String> {
    let args_copy = args.to_vec();
    let mut args = args_copy.into_iter();
    let command = args.next().ok_or_else(|| tokens_usage("missing command"))?;
    if command != "create" && command != "rotate" {
        return Err(tokens_usage("unknown command"));
    }

    let mut name: Option<String> = None;
    let mut vault_selector: Option<String> = None;
    let mut prefixes: Vec<String> = Vec::new();
    let mut ops: Option<String> = None;
    let mut ttl: Option<String> = None;
    let mut owner_email: Option<String> = None;
    let mut owner_id: Option<String> = None;
    let mut issued_by_email: Option<String> = None;
    let mut token_id: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = args.next(),
            "--vault" => vault_selector = args.next(),
            "--prefix" => {
                let value = args
                    .next()
                    .ok_or_else(|| tokens_usage("missing --prefix"))?;
                prefixes.push(value);
            }
            "--ops" => ops = args.next(),
            "--ttl" => ttl = args.next(),
            "--owner-email" => owner_email = args.next(),
            "--owner-id" => owner_id = args.next(),
            "--issued-by-email" => issued_by_email = args.next(),
            "--token-id" => token_id = args.next(),
            _ => return Err(tokens_usage(&format!("unknown arg: {arg}"))),
        }
    }

    let name = name.ok_or_else(|| tokens_usage("missing --name"))?;
    let vault_selector = vault_selector.ok_or_else(|| tokens_usage("missing --vault"))?;
    if prefixes.is_empty() {
        return Err(tokens_usage("missing --prefix"));
    }
    let issued_by_email =
        issued_by_email.ok_or_else(|| tokens_usage("missing --issued-by-email"))?;
    if issued_by_email.trim().is_empty() {
        return Err(tokens_usage("invalid --issued-by-email"));
    }
    if owner_email.is_none() && owner_id.is_none() {
        owner_email = Some(SYSTEM_OWNER_EMAIL.to_string());
    }
    let owner = resolve_owner(db, owner_email.as_deref(), owner_id.as_deref()).await?;
    let ops = ops.unwrap_or_else(|| "read".to_string());
    let permissions = parse_ops(&ops)?;
    let expires_at = ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()?
        .map(|duration| Utc::now() + duration);

    let vault = resolve_shared_vault(db, &vault_selector).await?;
    let mut normalized_prefixes = Vec::new();
    let mut full_vault = false;
    for prefix in prefixes {
        if prefix.trim() == "/" {
            full_vault = true;
            continue;
        }
        normalized_prefixes.push(normalize_prefix(&prefix)?);
    }
    if full_vault && !normalized_prefixes.is_empty() {
        return Err("prefix '/' cannot be combined with other prefixes".to_string());
    }
    if !full_vault && normalized_prefixes.is_empty() {
        return Err(tokens_usage("missing --prefix"));
    }

    let scopes: Vec<String> = if full_vault {
        permissions
            .iter()
            .map(|permission| format!("{}:{permission}", vault.id))
            .collect()
    } else {
        normalized_prefixes
            .iter()
            .flat_map(|normalized_prefix| {
                permissions.iter().map(|permission| {
                    format!(
                        "{}/prefix:{}:{}",
                        vault.id, normalized_prefix.scope, permission
                    )
                })
            })
            .collect()
    };

    let token_suffix: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let token = format!("{SERVICE_ACCOUNT_PREFIX}{token_suffix}");
    let token_prefix: String = token.chars().take(SERVICE_ACCOUNT_PREFIX_LEN).collect();
    let params = passwords::KdfParams {
        algorithm: settings.config.auth.kdf.algorithm.clone(),
        iterations: settings.config.auth.kdf.iterations,
        memory_kb: settings.config.auth.kdf.memory_kb,
        parallelism: settings.config.auth.kdf.parallelism,
    };
    let token_hash = passwords::hash_service_token(&token, &settings.token_pepper, &params)
        .map_err(|_| "token_hash_failed".to_string())?;

    let now = Utc::now();
    let prefixes_display: Vec<String> = if full_vault {
        vec!["/".to_string()]
    } else {
        normalized_prefixes
            .iter()
            .map(|value| value.canonical.clone())
            .collect()
    };
    let token_description = TokenDescription {
        issued_by: issued_by_email,
        vault_id: vault.id.to_string(),
        vault_slug: vault.slug.clone(),
        prefix: prefixes_display.first().cloned(),
        prefixes: Some(prefixes_display.clone()),
        ops: permissions
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    };
    let description = Some(
        serde_json::to_string(&token_description)
            .map_err(|_| "description_encode_failed".to_string())?,
    );

    if rotate {
        let token_id = token_id.ok_or_else(|| tokens_usage("missing --token-id"))?;
        let token_id = token_id
            .parse::<uuid::Uuid>()
            .map_err(|_| "invalid token_id".to_string())?;
        let repo = ServiceAccountRepo::new(db);
        let session_repo = ServiceAccountSessionRepo::new(db);
        let mut account = repo
            .get_by_id(token_id)
            .await
            .map_err(|_| "service_account_not_found".to_string())?
            .ok_or_else(|| "service_account_not_found".to_string())?;
        if account.revoked_at.is_some() {
            return Err("service_account_revoked".to_string());
        }
        account.token_hash = token_hash;
        account.token_prefix = token_prefix;
        account.name = name;
        account.description = description;
        account.expires_at = expires_at;
        account.scopes = sqlx_core::types::Json(scopes);
        repo.update(&account)
            .await
            .map_err(|_| "service_account_update_failed".to_string())?;
        session_repo
            .revoke_by_service_account(account.id)
            .await
            .map_err(|_| "service_account_session_delete_failed".to_string())?;
    } else {
        let account = ServiceAccount {
            id: uuid::Uuid::now_v7(),
            owner_user_id: owner,
            name,
            description,
            token_hash,
            token_prefix,
            scopes: sqlx_core::types::Json(scopes),
            allowed_ips: None,
            expires_at,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            use_count: 0,
            created_at: now,
            revoked_at: None,
        };
        let repo = ServiceAccountRepo::new(db);
        repo.create(&account)
            .await
            .map_err(|_| "service_account_create_failed".to_string())?;
    }

    let output = serde_json::json!({
        "token": token,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn tokens_create_or_rotate_from_token(
    settings: &settings::Settings,
    db: &zann_db::PgPool,
    args: &[String],
    rotate: bool,
) -> Result<(), String> {
    let args_copy = args.to_vec();
    let mut args = args_copy.into_iter();
    let command = args.next().ok_or_else(|| tokens_usage("missing command"))?;
    if command != "create" && command != "rotate" {
        return Err(tokens_usage("unknown command"));
    }

    let mut name: Option<String> = None;
    let mut token: Option<String> = None;
    let mut token_file: Option<String> = None;
    let mut ttl: Option<String> = None;
    let mut owner_email: Option<String> = None;
    let mut owner_id: Option<String> = None;
    let mut issued_by_email: Option<String> = None;
    let mut token_id: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--name" => name = args.next(),
            "--token" => token = args.next(),
            "--token-file" => token_file = args.next(),
            "--ttl" => ttl = args.next(),
            "--owner-email" => owner_email = args.next(),
            "--owner-id" => owner_id = args.next(),
            "--issued-by-email" => issued_by_email = args.next(),
            "--token-id" => token_id = args.next(),
            _ => return Err(tokens_usage(&format!("unknown arg: {arg}"))),
        }
    }

    let name = name.ok_or_else(|| tokens_usage("missing --name"))?;
    if token.is_some() && token_file.is_some() {
        return Err(tokens_usage("use --token or --token-file, not both"));
    }
    let token = match (token, token_file) {
        (Some(token), None) => token,
        (None, Some(path)) => read_token_file(&path)?,
        (None, None) => {
            if let Ok(path) = std::env::var("ZANN_TOKEN_FILE") {
                read_token_file(&path)?
            } else {
                return Err(tokens_usage("missing --token"));
            }
        }
        (Some(_), Some(_)) => return Err(tokens_usage("use --token or --token-file, not both")),
    };
    let issued_by_email =
        issued_by_email.ok_or_else(|| tokens_usage("missing --issued-by-email"))?;
    if issued_by_email.trim().is_empty() {
        return Err(tokens_usage("invalid --issued-by-email"));
    }
    if owner_email.is_none() && owner_id.is_none() {
        owner_email = Some(SYSTEM_OWNER_EMAIL.to_string());
    }
    let owner = resolve_owner(db, owner_email.as_deref(), owner_id.as_deref()).await?;
    let expires_at = ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()?
        .map(|duration| Utc::now() + duration);

    let payload = parse_token_payload(&token)?;
    let scope_entries: Vec<ScopeEntry> = payload
        .scopes
        .iter()
        .map(|scope| parse_scope_entry(scope))
        .collect::<Result<_, _>>()?;

    if !scope_entries_shared(db, &scope_entries).await {
        return Err("shared vault scopes required".to_string());
    }

    if !scope_entries_match_encryption(db, &scope_entries, VaultEncryptionType::Server).await {
        return Err("server-encrypted vault scopes required".to_string());
    }

    let token_suffix: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let new_token = format!("{SERVICE_ACCOUNT_PREFIX}{token_suffix}");
    let token_prefix: String = new_token.chars().take(SERVICE_ACCOUNT_PREFIX_LEN).collect();
    let params = passwords::KdfParams {
        algorithm: settings.config.auth.kdf.algorithm.clone(),
        iterations: settings.config.auth.kdf.iterations,
        memory_kb: settings.config.auth.kdf.memory_kb,
        parallelism: settings.config.auth.kdf.parallelism,
    };
    let token_hash = passwords::hash_service_token(&new_token, &settings.token_pepper, &params)
        .map_err(|_| "token_hash_failed".to_string())?;

    if rotate {
        let token_id = token_id.ok_or_else(|| tokens_usage("missing --token-id"))?;
        let token_id = token_id
            .parse::<uuid::Uuid>()
            .map_err(|_| "invalid token_id".to_string())?;
        let repo = ServiceAccountRepo::new(db);
        let session_repo = ServiceAccountSessionRepo::new(db);
        let mut account = repo
            .get_by_id(token_id)
            .await
            .map_err(|_| "service_account_not_found".to_string())?
            .ok_or_else(|| "service_account_not_found".to_string())?;
        if account.revoked_at.is_some() {
            return Err("service_account_revoked".to_string());
        }
        account.token_hash = token_hash;
        account.token_prefix = token_prefix;
        account.name = name;
        account.description = Some(token.clone());
        account.expires_at = expires_at;
        repo.update(&account)
            .await
            .map_err(|_| "service_account_update_failed".to_string())?;
        session_repo
            .revoke_by_service_account(account.id)
            .await
            .map_err(|_| "service_account_session_delete_failed".to_string())?;
    } else {
        let account = ServiceAccount {
            id: uuid::Uuid::now_v7(),
            owner_user_id: owner,
            name,
            description: Some(token.clone()),
            token_hash,
            token_prefix,
            scopes: sqlx_core::types::Json(payload.scopes),
            allowed_ips: None,
            expires_at,
            last_used_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
            use_count: 0,
            created_at: Utc::now(),
            revoked_at: None,
        };
        let repo = ServiceAccountRepo::new(db);
        repo.create(&account)
            .await
            .map_err(|_| "service_account_create_failed".to_string())?;
    }

    let output = serde_json::json!({
        "token": new_token,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}

fn read_token_file(path: &str) -> Result<String, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("token file not accessible ({}): {}", path, err))?;
    let token = contents.trim();
    if token.is_empty() {
        return Err("token file is empty".to_string());
    }
    Ok(token.to_string())
}
