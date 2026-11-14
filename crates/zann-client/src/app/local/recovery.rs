//! Explicit, scoped local data recovery. Remote data is never changed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryScope {
    Account(String),
    Device,
}
#[derive(Clone, Debug)]
pub struct AccountLocation {
    pub storage_id: String,
    pub name: String,
    pub account_name: Option<String>,
    pub server_url: String,
    /// Authenticated principal, when a configured credential currently supplies one.
    pub key_binding: Option<(String, String)>,
}
#[derive(Clone, Debug)]
pub struct SetupAccount {
    pub location: AccountLocation,
    pub enrolled: bool,
    pub has_replica: bool,
}
#[derive(Clone, Debug)]
pub struct RecoveryPreview {
    pub id: String,
    pub scope: RecoveryScope,
    pub accounts: u64,
    pub items: u64,
    pub pending: u64,
    pub dirty: u64,
    pub local_history: u64,
}
impl RecoveryPreview {
    pub fn has_unsent(&self) -> bool {
        self.pending != 0 || self.dirty != 0 || self.local_history != 0
    }
}
#[derive(Clone, Debug)]
pub struct RecoveryOutcome {
    pub snapshot_path: String,
    pub device_reset: bool,
}
