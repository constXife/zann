use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;
use uuid::Uuid;

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
pub struct SharedVersionsArgs {
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub item_id: Option<Uuid>,
    #[arg(long)]
    pub limit: Option<i64>,
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
pub struct RotateArgs {
    #[command(subcommand)]
    pub command: RotateCommand,
}

#[derive(Subcommand)]
pub enum RotateCommand {
    Start(RotateStartArgs),
    Status(RotateStatusArgs),
    Candidate(RotateCandidateArgs),
    Commit(RotateCommitArgs),
    Abort(RotateAbortArgs),
    Recover(RotateRecoverArgs),
}

#[derive(Args)]
pub struct RotateStartArgs {
    pub path: String,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub raw: bool,
    #[arg(long, value_enum, default_value = "json")]
    pub format: RotateFormat,
    #[arg(long)]
    pub policy: Option<String>,
}

#[derive(Args)]
pub struct RotateStatusArgs {
    pub path: String,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Args)]
pub struct RotateCandidateArgs {
    pub path: String,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub raw: bool,
    #[arg(long, value_enum, default_value = "json")]
    pub format: RotateFormat,
}

#[derive(Args)]
pub struct RotateCommitArgs {
    pub path: String,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Args)]
pub struct RotateAbortArgs {
    pub path: String,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub reason: Option<String>,
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RotateRecoverArgs {
    pub path: String,
    #[arg(long)]
    pub vault: Option<String>,
    #[arg(long)]
    pub raw: bool,
    #[arg(long, value_enum, default_value = "json")]
    pub format: RotateFormat,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RotateFormat {
    Json,
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
