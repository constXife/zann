//! Privileged server-auth reset; personal custody descriptors are preserved.
use super::*;
impl AccountAccessRepo<'_> {
    pub async fn reset_recovery_in(
        conn: &mut PgConnection,
        user: Uuid,
        expected_row_version: i64,
        candidate: Uuid,
        hash: &str,
    ) -> AccessStoreResult<zann_core::api::account_access::SecurityReceipt> {
        let account = Self::lock_account_in(conn, user).await?;
        if !account.active || account.row_version != expected_row_version {
            return Err(AccountAccessStoreError::Conflict);
        }
        super::super::SessionRepo::invalidate_user_in(conn, user, None).await?;
        Self::revoke_all_in(conn, user).await?;
        let account = Self::lock_account_in(conn, user).await?;
        Self::activate_code_in(
            conn,
            user,
            account.security_revision,
            candidate,
            hash,
            false,
        )
        .await
    }
}
