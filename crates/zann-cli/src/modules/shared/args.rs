use clap::{Args, ValueEnum};
use std::path::PathBuf;

#[derive(Args)]
pub struct SharedListArgs {
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Prefix to filter by")]
    pub prefix: Option<String>,
    #[arg(long, help = "Limit number of results")]
    pub limit: Option<i64>,
    #[arg(long, help = "Pagination cursor")]
    pub cursor: Option<String>,
    #[arg(long, value_enum, default_value = "table", help = "Output format")]
    pub format: ListFormat,
}

#[derive(Args)]
pub struct SharedMaterializeArgs {
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Prefix to filter by")]
    pub prefix: Option<String>,
    #[arg(long, help = "Output directory")]
    pub out: PathBuf,
    #[arg(long, help = "Single field to materialize")]
    pub field: Option<String>,
    #[arg(long, help = "Skip files that are already up to date")]
    pub skip_unchanged: bool,
    #[arg(long, help = "Write files non-atomically (overwrite in place)")]
    pub no_atomic: bool,
    #[arg(long, default_value_t = 200, help = "Max items per page")]
    pub limit: i64,
}

#[derive(Args)]
pub struct RenderArgs {
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Template file to render")]
    pub template: PathBuf,
    #[arg(long, help = "Output file (defaults to stdout)")]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
pub struct GetArgs {
    pub path: String,
    pub key: Option<String>,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, value_enum, default_value = "json", help = "Output format")]
    pub format: GetFormat,
}

#[derive(Args)]
pub struct CreateArgs {
    /// Item path (e.g. "db/production" or "services/api-key")
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, default_value = "secret", help = "Item type")]
    pub type_id: String,
    #[arg(
        long,
        short = 'f',
        num_args = 2,
        value_names = ["KEY", "VALUE"],
        help = "Field key-value pair (can be repeated)"
    )]
    pub field: Vec<String>,
    #[arg(long, help = "Read payload as JSON from stdin")]
    pub stdin: bool,
}

#[derive(Args)]
pub struct UpdateArgs {
    /// Item path (e.g. "db/production")
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "New item type")]
    pub type_id: Option<String>,
    #[arg(
        long,
        short = 'f',
        num_args = 2,
        value_names = ["KEY", "VALUE"],
        help = "Field key-value pair (can be repeated)"
    )]
    pub field: Vec<String>,
    #[arg(long, help = "Read payload as JSON from stdin")]
    pub stdin: bool,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// Item path (e.g. "db/production")
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum GetFormat {
    Json,
    Kv,
    Env,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ListFormat {
    Table,
    Json,
}
