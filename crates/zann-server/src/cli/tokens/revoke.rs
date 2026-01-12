use chrono::Utc;
use zann_db::repo::ServiceAccountRepo;

use super::TokenRevokeArgs;

pub(super) async fn tokens_revoke(
    db: &zann_db::PgPool,
    args: &TokenRevokeArgs,
) -> Result<(), String> {
    let token_id = args
        .token_id
        .parse::<uuid::Uuid>()
        .map_err(|_| "invalid token_id".to_string())?;
    let repo = ServiceAccountRepo::new(db);
    let mut account = repo
        .get_by_id(token_id)
        .await
        .map_err(|err| {
            tracing::error!(event = "service_account_lookup_failed", error = %err);
            "service_account_not_found".to_string()
        })?
        .ok_or_else(|| "service_account_not_found".to_string())?;
    account.revoked_at = Some(Utc::now());
    repo.update(&account).await.map_err(|err| {
        tracing::error!(event = "service_account_revoke_failed", error = %err);
        "service_account_revoke_failed".to_string()
    })?;
    println!("token revoked");
    Ok(())
}
