use clap::{Args, Subcommand};
use uuid::Uuid;

#[derive(Args)]
pub struct ItemArgs {
    #[command(subcommand)]
    pub command: ItemCommand,
}

#[derive(Subcommand)]
pub enum ItemCommand {
    List(ItemListArgs),
    Create(ItemCreateArgs),
    Ensure(ItemEnsureArgs),
    Get(ItemGetArgs),
    Update(ItemUpdateArgs),
    Delete(ItemDeleteArgs),
}

#[derive(Args)]
pub struct ItemListArgs {
    pub vault_id: String,
}

#[derive(Args)]
pub struct ItemCreateArgs {
    pub vault_id: String,
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub type_id: String,
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long)]
    pub favorite: bool,
    #[arg(long)]
    pub payload_base64: String,
    #[arg(long)]
    pub version: Option<i64>,
}

#[derive(Args)]
pub struct ItemEnsureArgs {
    pub vault_id: String,
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub type_id: String,
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long)]
    pub favorite: bool,
    #[arg(long)]
    pub payload_base64: String,
    #[arg(long)]
    pub version: Option<i64>,
}

#[derive(Args)]
pub struct ItemGetArgs {
    pub vault_id: String,
    pub item_id: Uuid,
}

#[derive(Args)]
pub struct ItemUpdateArgs {
    pub vault_id: String,
    pub item_id: Uuid,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub type_id: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,
    #[arg(long)]
    pub favorite: Option<bool>,
    #[arg(long)]
    pub payload_base64: Option<String>,
    #[arg(long)]
    pub version: Option<i64>,
    #[arg(long)]
    pub base_version: Option<i64>,
}

#[derive(Args)]
pub struct ItemDeleteArgs {
    pub vault_id: String,
    pub item_id: Uuid,
}
