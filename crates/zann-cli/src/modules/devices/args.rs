use clap::{Args, Subcommand};
use uuid::Uuid;

#[derive(Args)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub command: DeviceCommand,
}

#[derive(Subcommand)]
pub enum DeviceCommand {
    List(DeviceListArgs),
    Current(DeviceCurrentArgs),
    Revoke(DeviceRevokeArgs),
}

#[derive(Args)]
pub struct DeviceListArgs {
    #[arg(long)]
    pub limit: Option<i64>,
    #[arg(long)]
    pub offset: Option<i64>,
    #[arg(long)]
    pub sort: Option<String>,
}

#[derive(Args)]
pub struct DeviceCurrentArgs {}

#[derive(Args)]
pub struct DeviceRevokeArgs {
    pub id: Uuid,
}
