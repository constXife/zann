use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Serialize;
use zann_db::repo::{ServiceAccountRepo, ServiceAccountSessionRepo};

use crate::domains::auth::core::passwords;
use crate::settings;

use super::models::resolve_owner;
use super::{tokens_usage, SERVICE_ACCOUNT_PREFIX, SERVICE_ACCOUNT_PREFIX_LEN, SYSTEM_OWNER_EMAIL};

pub(super) async fn tokens_rotate(
    settings: &settings::Settings,
    db: &zann_db::PgPool,
    mut args: impl Iterator<Item = String>,
) -> Result<(), String> {
    let token_id = args
        .next()
        .ok_or_else(|| tokens_usage("missing token_id"))?;
    if args.next().is_some() {
        return Err(tokens_usage("too many args"));
    }
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
    account.token_hash = token_hash;
    account.token_prefix = token_prefix;
    repo.update(&account)
        .await
        .map_err(|_| "service_account_rotate_failed".to_string())?;
    session_repo
        .revoke_by_service_account(account.id)
        .await
        .map_err(|_| "service_account_session_delete_failed".to_string())?;

    let output = serde_json::json!({
        "token": token,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct TokenRotateOutput {
    token: String,
}

#[allow(clippy::too_many_lines)]
pub(super) async fn tokens_rotate_old(
    settings: &settings::Settings,
    db: &zann_db::PgPool,
    args: &[String],
) -> Result<(), String> {
    let args_copy = args.to_vec();
    let mut args = args_copy.into_iter();
    let command = args.next().ok_or_else(|| tokens_usage("missing command"))?;
    if command != "rotate" {
        return Err(tokens_usage("unknown command"));
    }

    let mut token_id: Option<String> = None;
    let mut owner_email: Option<String> = None;
    let mut owner_id: Option<String> = None;
    let mut issued_by_email: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--token-id" => token_id = args.next(),
            "--owner-email" => owner_email = args.next(),
            "--owner-id" => owner_id = args.next(),
            "--issued-by-email" => issued_by_email = args.next(),
            _ => return Err(tokens_usage(&format!("unknown arg: {arg}"))),
        }
    }

    let token_id = token_id.ok_or_else(|| tokens_usage("missing --token-id"))?;
    let token_id = token_id
        .parse::<uuid::Uuid>()
        .map_err(|_| "invalid token id".to_string())?;
    if owner_email.is_none() && owner_id.is_none() {
        owner_email = Some(SYSTEM_OWNER_EMAIL.to_string());
    }
    let _owner = resolve_owner(db, owner_email.as_deref(), owner_id.as_deref()).await?;
    let issued_by_email =
        issued_by_email.ok_or_else(|| tokens_usage("missing --issued-by-email"))?;
    if issued_by_email.trim().is_empty() {
        return Err(tokens_usage("invalid --issued-by-email"));
    }

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
    repo.update(&account)
        .await
        .map_err(|_| "service_account_update_failed".to_string())?;
    session_repo
        .revoke_by_service_account(account.id)
        .await
        .map_err(|_| "service_account_session_delete_failed".to_string())?;

    let output = TokenRotateOutput { token };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}
