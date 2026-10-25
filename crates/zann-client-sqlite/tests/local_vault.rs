#![cfg(feature = "local-vault")]

#[path = "local_vault/backup_round_trip.rs"]
mod backup_round_trip;
#[path = "local_vault/config_compat.rs"]
mod config_compat;
#[path = "local_vault/master_password.rs"]
mod master_password;
#[path = "local_vault/remembered_unlock.rs"]
mod remembered_unlock;
#[path = "local_vault/remote_master_password.rs"]
mod remote_master_password;
#[path = "local_vault/snapshots.rs"]
mod snapshots;
#[path = "local_vault/verify.rs"]
mod verify;
