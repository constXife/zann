use clap::{Args, Subcommand};

#[derive(Args)]
pub struct LoginArgs {
    #[command(subcommand)]
    pub command: Option<LoginCommand>,
}

#[derive(Subcommand)]
pub enum LoginCommand {
    OidcDevice(LoginOidcArgs),
    Internal(LoginInternalArgs),
}

#[derive(Args)]
pub struct LoginOidcArgs {
    #[arg(long)]
    pub context: Option<String>,
}

#[derive(Args)]
pub struct LoginInternalArgs {
    #[arg(long)]
    pub email: String,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub device_name: Option<String>,
    #[arg(long)]
    pub device_platform: Option<String>,
    #[arg(long)]
    pub context: Option<String>,
}

#[derive(Args)]
pub struct LogoutArgs {
    #[arg(long)]
    pub context: Option<String>,
    #[arg(long)]
    pub token_name: Option<String>,
}
