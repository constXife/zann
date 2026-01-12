use chrono::Utc;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use zann_core::ServiceAccount;
use zann_db::repo::ServiceAccountRepo;

use crate::domains::auth::core::passwords;
use crate::settings;

use super::models::{
    normalize_prefix, parse_ops, parse_ttl, resolve_owner, resolve_shared_vault, TokenDescription,
};
use super::{
    TokenCreateArgs, SERVICE_ACCOUNT_PREFIX, SERVICE_ACCOUNT_PREFIX_LEN, SYSTEM_OWNER_EMAIL,
};

pub(super) async fn tokens_create(
    settings: &settings::Settings,
    db: &zann_db::PgPool,
    args: &TokenCreateArgs,
) -> Result<(), String> {
    let name = args.name.trim();
    if name.is_empty() {
        return Err("invalid name".to_string());
    }
    let target = args.target.trim();
    if target.is_empty() {
        return Err("invalid vault:prefixes".to_string());
    }
    let (vault_selector, prefixes_raw) = target
        .split_once(':')
        .ok_or_else(|| "invalid vault:prefixes".to_string())?;
    let vault_selector = vault_selector.trim();
    if vault_selector.is_empty() {
        return Err("invalid vault:prefixes".to_string());
    }
    let prefixes_raw = prefixes_raw.trim();
    if prefixes_raw.is_empty() {
        return Err("missing prefix".to_string());
    }
    let issued_by_email = args
        .issued_by_email
        .as_deref()
        .unwrap_or(SYSTEM_OWNER_EMAIL)
        .trim();
    if issued_by_email.is_empty() {
        return Err("invalid issued-by-email".to_string());
    }

    let mut owner_email = args.owner_email.as_deref();
    let owner_id = args.owner_id.as_deref();
    if owner_email.is_none() && owner_id.is_none() {
        owner_email = Some(SYSTEM_OWNER_EMAIL);
    }
    let owner = resolve_owner(db, owner_email, owner_id).await?;
    let permissions = parse_ops(&args.ops)?;
    let expires_at = args
        .ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()?
        .map(|duration| Utc::now() + duration);

    let vault = resolve_shared_vault(db, vault_selector).await?;
    let mut normalized_prefixes = Vec::new();
    let mut full_vault = false;
    for prefix in prefixes_raw.split(',') {
        let prefix = prefix.trim();
        if prefix.is_empty() {
            return Err("invalid prefix".to_string());
        }
        if prefix == "/" {
            full_vault = true;
            continue;
        }
        normalized_prefixes.push(normalize_prefix(prefix)?);
    }
    if full_vault && !normalized_prefixes.is_empty() {
        return Err("prefix '/' cannot be combined with other prefixes".to_string());
    }
    if !full_vault && normalized_prefixes.is_empty() {
        return Err("missing --prefix".to_string());
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
        .map_err(|err| {
            tracing::error!(event = "token_hash_failed", error = %err);
            "token_hash_failed".to_string()
        })?;

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
        issued_by: issued_by_email.to_string(),
        vault_id: vault.id.to_string(),
        vault_slug: vault.slug.clone(),
        prefix: prefixes_display.first().cloned(),
        prefixes: Some(prefixes_display.clone()),
        ops: permissions
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    };
    let description = Some(serde_json::to_string(&token_description).map_err(|err| {
        tracing::error!(event = "description_encode_failed", error = %err);
        "description_encode_failed".to_string()
    })?);
    let account = ServiceAccount {
        id: uuid::Uuid::now_v7(),
        owner_user_id: owner,
        name: name.to_string(),
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
    repo.create(&account).await.map_err(|err| {
        tracing::error!(event = "service_account_create_failed", error = %err);
        "service_account_create_failed".to_string()
    })?;

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
        serde_json::to_string_pretty(&output).map_err(|err| {
            tracing::error!(event = "token_output_failed", error = %err);
            err.to_string()
        })?
    );
    Ok(())
}
