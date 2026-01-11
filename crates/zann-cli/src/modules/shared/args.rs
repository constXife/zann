use clap::{Args, ValueEnum};
use std::path::PathBuf;

#[derive(Args)]
pub struct SharedListArgs {
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub prefix: Option<String>,
    #[arg(long)]
    pub limit: Option<i64>,
    #[arg(long)]
    pub cursor: Option<String>,
    #[arg(long, value_enum, default_value = "table")]
    pub format: ListFormat,
}

#[derive(Args)]
pub struct SharedMaterializeArgs {
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub prefix: Option<String>,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long)]
    pub field: Option<String>,
    #[arg(long)]
    pub skip_unchanged: bool,
    #[arg(long)]
    pub no_atomic: bool,
    #[arg(long, default_value_t = 200)]
    pub limit: i64,
}

#[derive(Args)]
pub struct RenderArgs {
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub template: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
pub struct GetArgs {
    pub path: String,
    pub key: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long, value_enum, default_value = "json")]
    pub format: GetFormat,
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
