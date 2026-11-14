use crate::{domains::backup, settings};
use clap::Args;
use std::path::PathBuf;
use zann_db::PgPool;

#[derive(Debug, Clone, Args)]
pub struct ExportArgs {
    #[arg(
        long,
        value_name = "slug-or-id",
        conflicts_with = "all_shared",
        help = "Shared vault slug or UUID to export; repeat to export multiple vaults"
    )]
    pub vault: Vec<String>,
    #[arg(
        long,
        conflicts_with = "vault",
        help = "Export all shared server-encrypted vaults"
    )]
    pub all_shared: bool,
    #[arg(long, help = "Include deleted items in the export")]
    pub include_deleted: bool,
    #[arg(
        long,
        value_name = "path",
        help = "Write the plaintext export to a file instead of stdout"
    )]
    pub out: Option<PathBuf>,
    #[arg(
        long,
        help = "Required confirmation for plaintext export of shared secrets"
    )]
    pub i_understand_plaintext: bool,
}

pub(crate) async fn run(
    settings: &settings::Settings,
    db: &PgPool,
    args: &ExportArgs,
) -> Result<(), backup::BackupError> {
    let smk = settings
        .server_master_key
        .as_ref()
        .ok_or(backup::BackupError::Invalid("server_master_key_missing"))?;
    backup::export(
        db,
        smk,
        &backup::ExportOptions {
            vaults: args.vault.clone(),
            all_shared: args.all_shared,
            include_deleted: args.include_deleted,
            output: args.out.clone(),
            confirmed: args.i_understand_plaintext,
        },
    )
    .await
}
