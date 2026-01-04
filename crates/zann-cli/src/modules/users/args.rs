use clap::{Args, Subcommand};
use uuid::Uuid;

#[derive(Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCommand,
}

#[derive(Subcommand)]
pub enum UserCommand {
    List(UserListArgs),
    Create(UserCreateArgs),
    Get(UserGetArgs),
    Delete(UserDeleteArgs),
    Block(UserBlockArgs),
    Unblock(UserUnblockArgs),
    ResetPassword(UserResetPasswordArgs),
}

#[derive(Args)]
pub struct UserListArgs {
    #[arg(long)]
    pub status: Option<String>,
    #[arg(long)]
    pub limit: Option<i64>,
    #[arg(long)]
    pub offset: Option<i64>,
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(Args)]
pub struct UserCreateArgs {
    #[arg(long)]
    pub email: String,
    #[arg(long)]
    pub password: String,
    #[arg(long)]
    pub full_name: Option<String>,
}

#[derive(Args)]
pub struct UserGetArgs {
    pub id: Uuid,
}

#[derive(Args)]
pub struct UserDeleteArgs {
    pub id: Uuid,
}

#[derive(Args)]
pub struct UserBlockArgs {
    pub id: Uuid,
}

#[derive(Args)]
pub struct UserUnblockArgs {
    pub id: Uuid,
}

#[derive(Args)]
pub struct UserResetPasswordArgs {
    pub id: Uuid,
    #[arg(long)]
    pub password: Option<String>,
}
