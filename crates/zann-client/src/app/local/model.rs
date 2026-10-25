//! Local vault read models and commands.

#[derive(Debug, Clone)]
pub struct VaultStatus {
    pub unlocked: bool,
}

#[derive(Debug, Clone)]
pub struct VaultSummary {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub is_default: bool,
    pub item_count: u64,
}

#[derive(Debug, Clone)]
pub struct ItemsFilter {
    pub query: Option<String>,
    pub include_deleted: bool,
}

#[derive(Debug, Clone)]
pub struct Page {
    pub limit: u32,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone)]
pub struct ItemCountsView {
    pub all: u64,
    pub trash: u64,
    pub by_type: Vec<ItemTypeCount>,
}

#[derive(Debug, Clone)]
pub struct ItemTypeCount {
    pub type_id: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct ItemPage {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
    pub total_count: u64,
    pub counts: ItemCountsView,
}

#[derive(Clone)]
pub struct ItemDetail {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

impl std::fmt::Debug for ItemDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemDetail(<redacted>)")
    }
}

#[derive(Clone)]
pub struct ItemCreate {
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

impl std::fmt::Debug for ItemCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemCreate(<redacted>)")
    }
}

#[derive(Clone)]
pub struct ItemUpdate {
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

impl std::fmt::Debug for ItemUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemUpdate(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub struct ItemHistorySummary {
    pub version: i64,
    pub checksum: String,
    pub change_type: i32,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
    pub pending: bool,
}

#[derive(Clone)]
pub struct ItemHistoryDetail {
    pub version: i64,
    pub payload_json: String,
}

impl std::fmt::Debug for ItemHistoryDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemHistoryDetail(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub struct BackupImportOptions {
    /// Storage to import into. `None` — or the string `"local"` — means the
    /// local-only storage. A remote storage is not supported here yet: that
    /// path is not exposed through the canonical `zann-client::app` facade yet,
    /// and it reports `Unimplemented` rather than importing into the wrong
    /// place.
    pub target_storage_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BackupExportReport {
    pub path: String,
    pub storages_count: u64,
    pub vaults_count: u64,
    pub items_count: u64,
}

#[derive(Debug, Clone)]
pub struct BackupImportReport {
    pub imported_items: u64,
    pub skipped_existing: u64,
    pub skipped_missing_storage: u64,
    pub skipped_missing_vault: u64,
    pub skipped_deleted: u64,
}

#[derive(Debug, Clone)]
pub struct ApplePasswordsPreflight {
    pub total_rows: u64,
    pub importable_items: u64,
    pub duplicate_rows: u64,
    pub invalid_rows: u64,
}

#[derive(Debug, Clone)]
pub struct ApplePasswordsImportReport {
    pub imported_items: u64,
    pub renamed_items: u64,
    pub skipped_invalid: u64,
}

/// A point-in-time copy of the vault database. Still encrypted — unlike the
/// plaintext JSON an export produces — so it is only good for going back, not
/// for leaving.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub path: String,
    /// The KDF salt this copy needs to be opened. A database copy without it
    /// cannot be unlocked by any password, so a client offering to restore must
    /// keep the two together.
    pub identity_path: Option<String>,
    /// RFC 3339.
    pub created_at: String,
    pub size_bytes: u64,
}

/// What a restore did. Both paths are shown to the user: the one that was put
/// back, and the one holding what it displaced, which is how the restore is
/// undone.
#[derive(Debug, Clone)]
pub struct SnapshotRestore {
    pub restored_from: String,
    pub replaced_saved_to: String,
    /// The snapshot brought its own KDF salt. The vault now opens with the
    /// password that was in use when it was taken, and any remembered unlock has
    /// been dropped.
    pub identity_replaced: bool,
}

/// One fault found by [`LocalVault::verify`].
#[derive(Debug, Clone)]
pub struct VerifyProblem {
    /// `database`, `vault_key_unusable`, `checksum_mismatch` or
    /// `decrypt_failed`. Stable identifier for the UI to translate; the detail
    /// text is not.
    pub kind: String,
    pub vault_name: Option<String>,
    pub item_path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub database_ok: bool,
    pub vaults_checked: u64,
    pub vaults_skipped: u64,
    pub items_checked: u64,
    pub items_ok: u64,
    pub problems: Vec<VerifyProblem>,
}

/// How many snapshots to keep. `None` on either field disables that limit.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub max_count: Option<u32>,
    pub max_age_days: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct StorageSummary {
    pub id: String,
    pub name: String,
    pub kind: String, // "local" or "remote"
}

#[derive(Debug, Clone)]
pub struct AppStatus {
    pub initialized: bool, // master password has been set (vaults exist)
    pub locked: bool,
    pub storages_count: u64,
    pub has_local_vault: bool,
}

/// One enrolled authenticator, as the UI needs to show it. The wrapped master
/// key is deliberately absent: clients list and label keys, they do not handle
/// key material.
#[derive(Debug, Clone)]
pub struct HardwareKey {
    pub label: String,
    pub credential_id: String,
    pub enrolled_at: String,
}

#[derive(Debug, Clone)]
pub struct RememberedUnlock {
    /// Whether this device can unlock without the master password.
    pub armed: bool,
    /// "keystore" or "hardware_key".
    pub source: String,
    pub hardware_keys: Vec<HardwareKey>,
    /// Whether hardware keys work on this platform at all.
    pub hardware_supported: bool,
}

#[derive(Debug, Clone)]
pub struct LocalSyncOutcome {
    pub status: String,
    pub vaults_reconciled: u32,
    pub pages_committed: u32,
    pub changes_committed: u32,
}

use crate::app::{SyncOutcome, SyncOutcomeStatus};
impl From<SyncOutcome> for LocalSyncOutcome {
    fn from(outcome: SyncOutcome) -> Self {
        let status = match outcome.status() {
            SyncOutcomeStatus::Complete => "complete",
            SyncOutcomeStatus::CancelledPartial => "cancelled_partial",
            SyncOutcomeStatus::DeadlinePartial => "deadline_partial",
        };
        Self {
            status: status.to_string(),
            vaults_reconciled: u32::try_from(outcome.vaults_reconciled()).unwrap_or(u32::MAX),
            pages_committed: u32::try_from(outcome.pages_committed()).unwrap_or(u32::MAX),
            changes_committed: u32::try_from(outcome.changes_committed()).unwrap_or(u32::MAX),
        }
    }
}
