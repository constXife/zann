//! Break-glass access changes only server-auth authority, never E2EE ciphertext.
use crate::{config::AuthMode, settings::Settings};
use clap::{Args, Subcommand};
use std::{io::Write, path::PathBuf};
use uuid::Uuid;
use zann_db::{
    repo::{AccountAccessRepo, UserRepo},
    PgPool,
};
#[derive(Debug, Clone, Args)]
pub struct AdminArgs {
    #[command(subcommand)]
    pub command: AdminCommand,
}
#[derive(Debug, Clone, Subcommand)]
pub enum AdminCommand {
    /// Revoke all account sign-in keys/sessions and install a fresh one-use code.
    ResetRecoveryKey {
        #[arg(long)]
        email: String,
        /// New owner-only file; written and synced before changing server auth.
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("internal passkey recovery is disabled")]
    Disabled,
    #[error("account is absent, blocked or deleted")]
    Rejected,
    #[error("recovery key file operation failed")]
    Io(#[from] std::io::Error),
    #[error("recovery account lookup failed")]
    Database(#[from] sqlx_core::Error),
    #[error("recovery reset transaction failed")]
    Store(#[from] zann_db::repo::AccountAccessStoreError),
    #[error("recovery verifier derivation failed: {0}")]
    Kdf(&'static str),
}
pub async fn run(settings: &Settings, db: &PgPool, args: &AdminArgs) -> Result<(), AdminError> {
    if !settings.config.auth.internal.enabled
        || matches!(settings.config.auth.mode, AuthMode::Oidc)
        || settings.config.auth.passkey.is_none()
    {
        return Err(AdminError::Disabled);
    }
    let AdminCommand::ResetRecoveryKey { email, out } = &args.command;
    let user = UserRepo::new(db)
        .get_by_email(email)
        .await?
        .ok_or(AdminError::Rejected)?;
    if user.status != zann_core::UserStatus::Active || user.deleted_at.is_some() {
        return Err(AdminError::Rejected);
    }
    let code = zann_crypto::recovery::generate_server_recovery_key();
    let params = crate::domains::auth::core::passwords::kdf_params_from_user(&user);
    let hash = zann_crypto::recovery::server_recovery_verifier(
        &code,
        &user.kdf_salt,
        &settings.password_pepper,
        &params,
    )
    .map_err(AdminError::Kdf)?;
    let candidate = Uuid::new_v4();
    // Durable delivery precedes reset. create_new refuses existing files and
    // symlink targets; initial permissions are private before any secret write.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(out)?;
    writeln!(
        file,
        "Zann Server Recovery Key\nAccount: {}\nCandidate: {candidate}\n{}",
        user.email,
        code.as_str()
    )?;
    file.sync_all()?;
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    let mut tx = db.begin().await?;
    crate::infra::db::apply_tx_isolation(&mut tx, settings.db_tx_isolation).await?;
    sqlx_core::query::query::<sqlx_postgres::Postgres>("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    let receipt =
        AccountAccessRepo::reset_recovery_in(&mut tx, user.id, user.row_version, candidate, &hash)
            .await?;
    tx.commit().await?;
    println!(
        "Recovery reset committed: account={}, candidate={}, version={}",
        user.id,
        candidate,
        receipt.recovery_key_version.ok_or(AdminError::Rejected)?
    );
    Ok(())
}
