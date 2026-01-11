use clap::{Args, Subcommand};

#[derive(Args)]
pub struct ServerArgs {
    #[command(subcommand)]
    pub command: ServerCommand,
}

#[derive(Subcommand)]
pub enum ServerCommand {
    Info(ServerInfoArgs),
}

#[derive(Args)]
pub struct ServerInfoArgs {
    pub addr: Option<String>,
}

#[derive(Args)]
pub struct RunArgs {
    pub path: String,
    #[arg(long)]
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
    SetContext(SetContextArgs),
    UseContext(UseContextArgs),
    CurrentContext,
    GetContexts,
    UseToken(UseTokenArgs),
    ListTokens(ListTokensArgs),
    ShowToken(ShowTokenArgs),
    RemoveToken(RemoveTokenArgs),
}

#[derive(Args)]
pub struct SetContextArgs {
    pub name: String,
    #[arg(long)]
    pub addr: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
    #[arg(long)]
    pub token_name: Option<String>,
    #[arg(long)]
    pub vault: Option<String>,
}

#[derive(Args)]
pub struct UseContextArgs {
    pub name: String,
}

#[derive(Args)]
pub struct UseTokenArgs {
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
    pub name: String,
    #[arg(long)]
    pub show_service_token: bool,
    #[arg(long)]
    pub context: Option<String>,
}

#[derive(Args)]
pub struct RemoveTokenArgs {
    pub name: String,
    #[arg(long)]
    pub context: Option<String>,
}
