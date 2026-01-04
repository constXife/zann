use zann_db::repo::{ServiceAccountRepo, UserRepo};

use super::models::{
    parse_description, parse_scope_for_list, resolve_owner, resolve_vault_for_list, ParsedScope,
    ScopeSummary, TokenListRow,
};
use super::{tokens_usage, SYSTEM_OWNER_EMAIL};

pub(super) async fn tokens_list(
    db: &zann_db::PgPool,
    mut args: impl Iterator<Item = String>,
) -> Result<(), String> {
    let mut owner_email: Option<String> = None;
    let mut owner_id: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--owner-email" => owner_email = args.next(),
            "--owner-id" => owner_id = args.next(),
            _ => return Err(tokens_usage(&format!("unknown arg: {arg}"))),
        }
    }
    if owner_email.is_none() && owner_id.is_none() {
        owner_email = Some(SYSTEM_OWNER_EMAIL.to_string());
    }
    let owner = resolve_owner(db, owner_email.as_deref(), owner_id.as_deref()).await?;
    let repo = ServiceAccountRepo::new(db);
    let accounts = repo
        .list_by_owner(owner, 200, 0, "desc")
        .await
        .map_err(|_| "service_account_list_failed".to_string())?;

    let user_repo = UserRepo::new(db);
    let mut rows = Vec::new();
    for account in accounts {
        let description = account
            .description
            .as_deref()
            .and_then(|value| parse_description(value).ok());
        let parsed_scopes: Vec<ParsedScope> = account
            .scopes
            .0
            .iter()
            .filter_map(|scope| parse_scope_for_list(scope))
            .collect();
        let scope_summary = ScopeSummary::from_scopes(&parsed_scopes);
        let owner_email = user_repo
            .get_by_id(account.owner_user_id)
            .await
            .ok()
            .flatten()
            .map(|user| user.email);
        let vault = match description.as_ref() {
            Some(value) => resolve_vault_for_list(db, value).await,
            None => None,
        };
        rows.push(TokenListRow {
            id: account.id,
            name: account.name,
            owner_email,
            issued_by: description.as_ref().map(|value| value.issued_by.clone()),
            created_at: account.created_at.to_rfc3339(),
            expires_at: account.expires_at.map(|value| value.to_rfc3339()),
            last_used_at: account.last_used_at.map(|value| value.to_rfc3339()),
            revoked_at: account.revoked_at.map(|value| value.to_rfc3339()),
            vault_id: description.as_ref().map(|value| value.vault_id.clone()),
            vault_slug: description.as_ref().map(|value| value.vault_slug.clone()),
            vault_name: vault.as_ref().map(|value| value.name.clone()),
            vault_kind: vault.as_ref().map(|value| value.kind.as_str().to_string()),
            scopes: scope_summary.scopes,
            scope_summary: scope_summary.summary,
        });
    }

    let output = serde_json::json!({
        "tokens": rows,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?
    );
    Ok(())
}
