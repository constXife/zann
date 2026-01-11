use clap::{ArgAction, Parser, Subcommand};

pub use crate::modules::auth::args::*;
pub use crate::modules::shared::args::*;
pub use crate::modules::system::args::*;

#[derive(Parser)]
#[command(name = "zann")]
#[command(about = "Zann CLI")]
pub struct Cli {
    #[arg(long, env = "ZANN_ADDR")]
    pub addr: Option<String>,
    #[arg(long, env = "ZANN_TOKEN")]
    pub token: Option<String>,
    #[arg(long, env = "ZANN_TOKEN_FILE")]
    pub token_file: Option<String>,
    #[arg(long)]
    pub token_name: Option<String>,
    #[arg(long)]
    pub context: Option<String>,
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,
    #[arg(long, help = "Allow http:// and invalid TLS certificates")]
    pub insecure: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Server(ServerArgs),
    Run(RunArgs),
    Whoami,
    List(SharedListArgs),
    #[command(about = "Materialize secrets into files (shared vaults)")]
    Materialize(SharedMaterializeArgs),
    Render(RenderArgs),
    Config(ConfigArgs),
    Login(LoginArgs),
    Logout(LogoutArgs),
    Get(GetArgs),
}
