use chrono::Utc;
use serde::Serialize;
use zann_db::repo::ServiceAccountRepo;

use super::models::resolve_owner;
use super::{tokens_usage, SYSTEM_OWNER_EMAIL};

pub(super) async fn tokens_revoke(
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
    let mut account = repo
        .get_by_id(token_id)
        .await
        .map_err(|_| "service_account_not_found".to_string())?
        .ok_or_else(|| "service_account_not_found".to_string())?;
    account.revoked_at = Some(Utc::now());
    repo.update(&account)
        .await
        .map_err(|_| "service_account_revoke_failed".to_string())?;
    println!("token revoked");
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct TokenRevokeOutput {
    revoked: bool,
}

#[allow(clippy::too_many_lines)]
pub(super) async fn tokens_revoke_old(db: &zann_db::PgPool, args: &[String]) -> Result<(), String> {
    let args_copy = args.to_vec();
    let mut args = args_copy.into_iter();
    let command = args.next().ok_or_else(|| tokens_usage("missing command"))?;
    if command != "revoke" {
        return Err(tokens_usage("unknown command"));
    }

    let mut token_id: Option<String> = None;
    let mut owner_email: Option<String> = None;
    let mut owner_id: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--token-id" => token_id = args.next(),
            "--owner-email" => owner_email = args.next(),
            "--owner-id" => owner_id = args.next(),
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

    let repo = ServiceAccountRepo::new(db);
    let mut account = repo
        .get_by_id(token_id)
        .await
        .map_err(|_| "service_account_not_found".to_string())?
        .ok_or_else(|| "service_account_not_found".to_string())?;
    if account.revoked_at.is_some() {
        return Err("service_account_revoked".to_string());
    }
    account.revoked_at = Some(Utc::now());
    repo.update(&account)
        .await
        .map_err(|_| "service_account_update_failed".to_string())?;

    let output = TokenRevokeOutput { revoked: true };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}
