use crate::{domains::backup, settings};
use clap::Args;
use std::path::PathBuf;
use zann_db::PgPool;

#[derive(Debug, Clone, Args)]
pub struct ImportArgs {
    #[arg(
        long,
        value_name = "path",
        help = "Private plaintext shared-vault export to restore"
    )]
    pub input: PathBuf,
    #[arg(
        long,
        help = "Existing active account that will administer recreated vaults"
    )]
    pub owner_email: String,
    #[arg(long, help = "Required confirmation for reading plaintext secrets")]
    pub i_understand_plaintext: bool,
}

pub(crate) async fn run(
    settings: &settings::Settings,
    db: &PgPool,
    args: ImportArgs,
) -> Result<(), backup::BackupError> {
    let smk = settings
        .server_master_key
        .as_ref()
        .ok_or(backup::BackupError::Invalid("server_master_key_missing"))?;
    let report = backup::import_file(
        db,
        smk,
        backup::ImportOptions {
            input: args.input,
            owner_email: args.owner_email,
            confirmed: args.i_understand_plaintext,
        },
    )
    .await?;
    eprintln!(
        "Restored {} shared vaults and {} items",
        report.vaults, report.items
    );
    Ok(())
}
