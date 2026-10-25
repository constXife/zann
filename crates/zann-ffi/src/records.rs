#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultStatus {
    pub unlocked: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VaultSummaryFfi {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub is_default: bool,
    pub item_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemsFilter {
    pub query: Option<String>,
    pub include_deleted: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Page {
    pub limit: u32,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemCountsFfi {
    pub all: u64,
    pub trash: u64,
    pub by_type: Vec<ItemTypeCount>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemTypeCount {
    pub type_id: String,
    pub count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemPage {
    pub items: Vec<ItemSummary>,
    pub next_cursor: Option<String>,
    pub total_count: u64,
    pub counts: ItemCountsFfi,
}

#[derive(Clone, uniffi::Record)]
pub struct ItemDetail {
    pub id: String,
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

#[derive(Clone, uniffi::Record)]
pub struct ItemCreate {
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

#[derive(Clone, uniffi::Record)]
pub struct ItemUpdate {
    pub title: String,
    pub path: String,
    pub type_id: String,
    pub payload_json: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ItemHistorySummaryFfi {
    pub version: i64,
    pub checksum: String,
    pub change_type: i32,
    pub changed_by_name: Option<String>,
    pub changed_by_email: String,
    pub created_at: String,
    pub pending: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct ItemHistoryDetailFfi {
    pub version: i64,
    pub payload_json: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupImportOptions {
    /// Storage to import into. `None` — or the string `"local"` — means the
    /// local-only storage. A remote storage is not supported here yet: that
    /// path is not exposed through the canonical `zann-client::app` facade yet,
    /// and it reports `Unimplemented` rather than importing into the wrong
    /// place.
    pub target_storage_id: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupExportReport {
    pub path: String,
    pub storages_count: u64,
    pub vaults_count: u64,
    pub items_count: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct BackupImportReport {
    pub imported_items: u64,
    pub skipped_existing: u64,
    pub skipped_missing_storage: u64,
    pub skipped_missing_vault: u64,
    pub skipped_deleted: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ApplePasswordsPreflightFfi {
    pub total_rows: u64,
    pub importable_items: u64,
    pub duplicate_rows: u64,
    pub invalid_rows: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ApplePasswordsImportReportFfi {
    pub imported_items: u64,
    pub renamed_items: u64,
    pub skipped_invalid: u64,
}

/// A point-in-time copy of the vault database. Still encrypted — unlike the
/// plaintext JSON an export produces — so it is only good for going back, not
/// for leaving.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SnapshotFfi {
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
#[derive(Debug, Clone, uniffi::Record)]
pub struct SnapshotRestoreFfi {
    pub restored_from: String,
    pub replaced_saved_to: String,
    /// The snapshot brought its own KDF salt. The vault now opens with the
    /// password that was in use when it was taken, and any remembered unlock has
    /// been dropped.
    pub identity_replaced: bool,
}

/// One fault found by [`CoreFacade::verify`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifyProblemFfi {
    /// `database`, `vault_key_unusable`, `checksum_mismatch` or
    /// `decrypt_failed`. Stable identifier for the UI to translate; the detail
    /// text is not.
    pub kind: String,
    pub vault_name: Option<String>,
    pub item_path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct VerifyReportFfi {
    pub database_ok: bool,
    pub vaults_checked: u64,
    pub vaults_skipped: u64,
    pub items_checked: u64,
    pub items_ok: u64,
    pub problems: Vec<VerifyProblemFfi>,
}

/// How many snapshots to keep. `None` on either field disables that limit.
#[derive(Debug, Clone, Copy, uniffi::Record)]
pub struct RetentionFfi {
    pub max_count: Option<u32>,
    pub max_age_days: Option<i64>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StorageSummaryFfi {
    pub id: String,
    pub name: String,
    pub kind: String, // "local" or "remote"
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AppStatusFfi {
    pub initialized: bool, // master password has been set (vaults exist)
    pub locked: bool,
    pub storages_count: u64,
    pub has_local_vault: bool,
}

/// One enrolled authenticator, as the UI needs to show it. The wrapped master
/// key is deliberately absent: clients list and label keys, they do not handle
/// key material.
#[derive(Debug, Clone, uniffi::Record)]
pub struct HardwareKeyFfi {
    pub label: String,
    pub credential_id: String,
    pub enrolled_at: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RememberedUnlockFfi {
    /// Whether this device can unlock without the master password.
    pub armed: bool,
    /// "keystore" or "hardware_key".
    pub source: String,
    pub hardware_keys: Vec<HardwareKeyFfi>,
    /// Whether hardware keys work on this platform at all.
    pub hardware_supported: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SyncOutcomeFfi {
    pub status: String,
    pub vaults_reconciled: u32,
    pub pages_committed: u32,
    pub changes_committed: u32,
}

impl zann_ui_core::ItemLike for ItemSummary {
    fn title(&self) -> &str {
        &self.title
    }

    fn type_id(&self) -> &str {
        &self.type_id
    }

    fn path(&self) -> &str {
        &self.path
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }
}

impl From<&ItemCountsFfi> for zann_ui_core::ItemCounts {
    fn from(counts: &ItemCountsFfi) -> Self {
        Self {
            all: counts.all,
            trash: counts.trash,
            by_type: counts
                .by_type
                .iter()
                .map(|entry| (entry.type_id.clone(), entry.count))
                .collect(),
        }
    }
}

impl std::fmt::Debug for ItemDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemDetail(<redacted>)")
    }
}

impl std::fmt::Debug for ItemCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemCreate(<redacted>)")
    }
}

impl std::fmt::Debug for ItemUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemUpdate(<redacted>)")
    }
}

impl std::fmt::Debug for ItemHistoryDetailFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ItemHistoryDetailFfi(<redacted>)")
    }
}
