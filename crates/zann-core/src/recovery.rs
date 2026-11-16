//! Value-only recovery state shared by persistence and native auth intents.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_CLIENT_RECOVERY_OPERATIONS: usize = 4;
pub const MAX_ACTIVE_RECOVERY_OPERATIONS: i64 = 1_024;
pub const MAX_RETAINED_RECOVERY_OPERATIONS: i64 = 8_192;
pub const MAX_RECOVERY_RECEIPTS: i16 = 32;
pub const RECOVERY_LIFETIME_HOURS: i64 = 24;
pub const RECOVERY_RETENTION_DAYS: i64 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i16)]
pub enum RecoveryState {
    Consumed = 1,
    CredentialReady = 2,
    Completed = 3,
    Expired = 4,
    Abandoned = 5,
    Superseded = 6,
}
impl RecoveryState {
    pub fn from_code(value: i16) -> Option<Self> {
        match value {
            1 => Some(Self::Consumed),
            2 => Some(Self::CredentialReady),
            3 => Some(Self::Completed),
            4 => Some(Self::Expired),
            5 => Some(Self::Abandoned),
            6 => Some(Self::Superseded),
            _ => None,
        }
    }
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Consumed | Self::CredentialReady)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStatus {
    pub operation_id: Uuid,
    pub user_id: Uuid,
    pub auth_epoch: i64,
    pub account_key_epoch: Option<i64>,
    pub state: RecoveryState,
    pub revision: i64,
    pub expires_at: DateTime<Utc>,
}
impl RecoveryStatus {
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        !self.state.is_terminal() && self.expires_at > now
    }
}
