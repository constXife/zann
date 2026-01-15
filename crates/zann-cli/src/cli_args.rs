use clap::{ArgAction, Parser, Subcommand};

pub use crate::modules::shared::args::*;
pub use crate::modules::system::args::*;

#[derive(Parser)]
#[command(name = "zann")]
#[command(
    about = "Zann CLI (token-based; tokens are issued by the server)",
    long_about = "Zann CLI for shared vault access and automation. Authentication is token-based; tokens are issued and managed by the server.\nDocs: https://github.com/constXife/zann",
    version
)]
pub struct Cli {
    #[arg(long, env = "ZANN_ADDR", help = "Server base URL")]
    pub addr: Option<String>,
    #[arg(
        long,
        env = "ZANN_TOKEN",
        help = "Access or service token (issued by the server)"
    )]
    pub token: Option<String>,
    #[arg(
        long,
        env = "ZANN_TOKEN_FILE",
        help = "Path to a file with an access or service token (issued by the server)"
    )]
    pub token_file: Option<String>,
    #[arg(long, help = "Token name to use from the current context")]
    pub token_name: Option<String>,
    #[arg(long, help = "Context name to use from config")]
    pub context: Option<String>,
    #[arg(short, long, action = ArgAction::Count, help = "Increase verbosity (-v, -vv)")]
    pub verbose: u8,
    #[arg(long, help = "Allow http:// and invalid TLS certificates")]
    pub insecure: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    #[command(about = "Server metadata and diagnostics")]
    Server(ServerArgs),
    #[command(about = "Run a command with secrets injected as env vars")]
    Run(RunArgs),
    #[command(about = "Print the current identity for the token")]
    Whoami,
    #[command(about = "List secrets (shared vaults)")]
    List(SharedListArgs),
    #[command(about = "Materialize secrets into files (shared vaults)")]
    Materialize(SharedMaterializeArgs),
    #[command(about = "Render templates using secrets (shared vaults)")]
    Render(RenderArgs),
    #[command(about = "Manage local contexts and tokens")]
    Config(ConfigArgs),
    #[command(about = "Fetch a single secret item by path")]
    Get(GetArgs),
    #[command(about = "Print version information")]
    Version,
}
