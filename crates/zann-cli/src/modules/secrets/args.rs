use clap::{Args, Subcommand, ValueEnum};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Args)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCommand,
}

#[derive(Subcommand)]
pub enum SecretCommand {
    #[command(about = "List machine-secret metadata without reading values")]
    List(SecretListArgs),
    #[command(about = "Read one machine secret")]
    Get(SecretGetArgs),
    #[command(about = "Create or replace one machine secret")]
    Set(SecretSetArgs),
    #[command(about = "Create a generated machine secret if it is absent")]
    Ensure(SecretEnsureArgs),
    #[command(about = "Replace a machine secret with a newly generated value")]
    Rotate(SecretRotateArgs),
}

#[derive(Args)]
pub struct SecretListArgs {
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Restrict results to this path prefix")]
    pub prefix: Option<String>,
    #[arg(long, default_value_t = 50, help = "Page size (1-100)")]
    pub limit: usize,
    #[arg(long, help = "Opaque pagination cursor from the previous page")]
    pub cursor: Option<String>,
    #[arg(long, value_enum, default_value = "table", help = "Output format")]
    pub format: SecretListOutputFormat,
}

#[derive(Args)]
pub struct SecretGetArgs {
    #[arg(help = "Secret item path")]
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(
        long,
        help = "Read the immediately previous version within the server grace window"
    )]
    pub previous: bool,
    #[arg(long, value_enum, default_value = "value", help = "Output format")]
    pub format: SecretOutputFormat,
}

#[derive(Args)]
pub struct RotationHookArgs {
    #[arg(help = "Secret item path")]
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Server-side generation policy")]
    pub policy: Option<String>,
    #[arg(
        long,
        value_name = "PROGRAM",
        help = "Executable rotation hook (no shell)"
    )]
    pub exec: PathBuf,
    #[arg(
        long = "exec-arg",
        value_name = "ARG",
        help = "Argument passed to the hook; repeat for multiple arguments"
    )]
    pub exec_args: Vec<OsString>,
    #[arg(
        long,
        default_value_t = 300,
        value_parser = clap::value_parser!(u64).range(1..=86_400),
        help = "Hook timeout in seconds, additionally capped by rotation expiry"
    )]
    pub timeout_seconds: u64,
}

#[derive(Args)]
pub struct SecretEnsureArgs {
    #[arg(help = "Secret item path")]
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Server-side generation policy")]
    pub policy: Option<String>,
    #[arg(long, value_enum, default_value = "value", help = "Output format")]
    pub format: SecretOutputFormat,
}

#[derive(Args)]
pub struct SecretRotateArgs {
    #[arg(help = "Secret item path")]
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(long, help = "Server-side generation policy")]
    pub policy: Option<String>,
    #[arg(long, value_enum, default_value = "value", help = "Output format")]
    pub format: SecretOutputFormat,
}

#[derive(Args)]
pub struct SecretSetArgs {
    #[arg(help = "Secret item path")]
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "stdin",
        conflicts_with = "stdin",
        help = "Read the exact UTF-8 secret value from a file"
    )]
    pub value_file: Option<PathBuf>,
    #[arg(
        long,
        required_unless_present = "value_file",
        conflicts_with = "value_file",
        help = "Read the exact UTF-8 secret value from standard input"
    )]
    pub stdin: bool,
    #[arg(long, help = "Server-side generation policy metadata")]
    pub policy: Option<String>,
    #[arg(long, value_enum, default_value = "value", help = "Output format")]
    pub format: SecretOutputFormat,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SecretOutputFormat {
    Value,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum SecretListOutputFormat {
    Table,
    Json,
}
