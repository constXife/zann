use clap::{Args, Subcommand};

#[derive(Args)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: ServerCommand,
}

#[derive(Subcommand)]
pub enum ServerCommand {
    #[command(about = "Show server info (fingerprint, auth methods, etc.)")]
    Info(ServerInfoArgs),
}

#[derive(Args)]
pub struct ServerInfoArgs {
    #[arg(help = "Server base URL (overrides --addr)")]
    pub addr: Option<String>,
}

#[derive(Args)]
pub struct RunArgs {
    #[arg(help = "Secret path to resolve (e.g. app/db/password)")]
    pub path: String,
    #[arg(long, help = "Vault name or ID")]
    pub vault: Option<String>,
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
}

#[derive(Subcommand)]
pub enum ConfigCommand {
    #[command(about = "Create or update a context")]
    SetContext(SetContextArgs),
    #[command(about = "Set the active context")]
    UseContext(UseContextArgs),
    #[command(about = "Print the active context name")]
    CurrentContext,
    #[command(about = "List known context names")]
    GetContexts,
    #[command(about = "Set the active token for a context")]
    UseToken(UseTokenArgs),
    #[command(about = "List tokens for a context")]
    ListTokens(ListTokensArgs),
    #[command(about = "Print a stored token by name")]
    ShowToken(ShowTokenArgs),
    #[command(about = "Remove a token from a context")]
    RemoveToken(RemoveTokenArgs),
}

#[derive(Args)]
pub struct SetContextArgs {
    #[arg(help = "Context name")]
    pub name: String,
    #[arg(long, help = "Server base URL")]
    pub addr: Option<String>,
    #[arg(long, help = "Access or service token (issued by the server)")]
    pub token: Option<String>,
    #[arg(long, help = "Token name to store in this context")]
    pub token_name: Option<String>,
    #[arg(long, help = "Default vault name or ID for this context")]
    pub vault: Option<String>,
}

#[derive(Args)]
pub struct UseContextArgs {
    #[arg(help = "Context name")]
    pub name: String,
}

#[derive(Args)]
pub struct UseTokenArgs {
    #[arg(help = "Token name")]
    pub name: String,
    #[arg(long)]
    pub context: Option<String>,
}

#[derive(Args)]
pub struct ListTokensArgs {
    #[arg(long)]
    pub context: Option<String>,
}

#[derive(Args)]
pub struct ShowTokenArgs {
    #[arg(help = "Token name")]
    pub name: String,
    #[arg(long, help = "Show the stored service token (issued by the server)")]
    pub show_service_token: bool,
    #[arg(long)]
    pub context: Option<String>,
}

#[derive(Args)]
pub struct RemoveTokenArgs {
    #[arg(help = "Token name")]
    pub name: String,
    #[arg(long)]
    pub context: Option<String>,
}
