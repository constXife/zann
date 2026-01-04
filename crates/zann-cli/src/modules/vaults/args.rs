use clap::{Args, Subcommand};

#[derive(Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub command: VaultCommand,
}

#[derive(Subcommand)]
pub enum VaultCommand {
    List(VaultListArgs),
    Create(VaultCreateArgs),
    Get(VaultGetArgs),
    Delete(VaultDeleteArgs),
}

#[derive(Args)]
pub struct VaultListArgs {
    #[arg(long)]
    pub limit: Option<i64>,
    #[arg(long)]
    pub offset: Option<i64>,
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(Args)]
pub struct VaultCreateArgs {
    #[arg(long)]
    pub slug: String,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub kind: String,
    #[arg(long)]
    pub cache_policy: String,
    #[arg(long)]
    pub vault_key_base64: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub tag: Vec<String>,
}

#[derive(Args)]
pub struct VaultGetArgs {
    pub id_or_slug: String,
}

#[derive(Args)]
pub struct VaultDeleteArgs {
    pub id_or_slug: String,
}
