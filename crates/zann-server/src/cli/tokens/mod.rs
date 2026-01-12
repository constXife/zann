use crate::settings;
use clap::{Args, Subcommand};
use zann_db::PgPool;

mod create;
mod list;
mod models;
mod revoke;

pub(super) const SERVICE_ACCOUNT_PREFIX: &str = "zann_sa_";
pub(super) const SERVICE_ACCOUNT_PREFIX_LEN: usize = 12;
pub(super) const SYSTEM_OWNER_EMAIL: &str = "system@zann.internal";

#[derive(Debug, Clone, Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TokenCommand {
    Create(TokenCreateArgs),
    List(TokenListArgs),
    Revoke(TokenRevokeArgs),
}

#[derive(Debug, Clone, Args)]
pub struct TokenCreateArgs {
    #[arg(value_name = "name")]
    pub name: String,
    #[arg(
        value_name = "vault:prefixes",
        help = "Vault selector and prefixes, e.g. prod:/ or prod:apps,infra"
    )]
    pub target: String,
    #[arg(
        value_name = "ops",
        default_value = "read",
        help = "Comma-separated ops (read, read_history, read_previous)"
    )]
    pub ops: String,
    #[arg(long)]
    pub ttl: Option<String>,
    #[arg(long)]
    pub owner_email: Option<String>,
    #[arg(long)]
    pub owner_id: Option<String>,
    #[arg(long)]
    pub issued_by_email: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct TokenListArgs {
    #[arg(long)]
    pub owner_email: Option<String>,
    #[arg(long)]
    pub owner_id: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct TokenRevokeArgs {
    pub token_id: String,
}

pub(crate) async fn run(
    settings: &settings::Settings,
    db: &PgPool,
    args: &TokenArgs,
) -> Result<(), String> {
    match &args.command {
        TokenCommand::Create(command) => create::tokens_create(settings, db, command).await,
        TokenCommand::List(command) => list::tokens_list(db, command).await,
        TokenCommand::Revoke(command) => revoke::tokens_revoke(db, command).await,
    }
}
