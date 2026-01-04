use clap::{ArgAction, Parser, Subcommand};

pub use crate::modules::auth::args::*;
pub use crate::modules::devices::args::*;
pub use crate::modules::groups::args::*;
pub use crate::modules::items::args::*;
pub use crate::modules::shared::args::*;
pub use crate::modules::system::args::*;
pub use crate::modules::users::args::*;
pub use crate::modules::vaults::args::*;

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
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Device(DeviceArgs),
    Server(ServerArgs),
    Run(RunArgs),
    Whoami,
    Types(TypesArgs),
    List(SharedListArgs),
    Versions(SharedVersionsArgs),
    #[command(about = "Materialize secrets into files (shared vaults)")]
    Materialize(SharedMaterializeArgs),
    Render(RenderArgs),
    User(UserArgs),
    Group(GroupArgs),
    Vault(VaultArgs),
    Item(ItemArgs),
    Config(ConfigArgs),
    Login(LoginArgs),
    Logout(LogoutArgs),
    Rotate(RotateArgs),
    Get(GetArgs),
}
