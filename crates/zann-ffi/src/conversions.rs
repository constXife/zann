use crate::records::*;
use zann_client::app::local as native;

impl From<native::VaultStatus> for VaultStatus {
    fn from(value: native::VaultStatus) -> Self {
        Self {
            unlocked: value.unlocked,
        }
    }
}

impl From<VaultStatus> for native::VaultStatus {
    fn from(value: VaultStatus) -> Self {
        Self {
            unlocked: value.unlocked,
        }
    }
}

impl From<native::VaultSummary> for VaultSummaryFfi {
    fn from(value: native::VaultSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            kind: value.kind,
            is_default: value.is_default,
            item_count: value.item_count,
        }
    }
}

impl From<VaultSummaryFfi> for native::VaultSummary {
    fn from(value: VaultSummaryFfi) -> Self {
        Self {
            id: value.id,
            name: value.name,
            kind: value.kind,
            is_default: value.is_default,
            item_count: value.item_count,
        }
    }
}

impl From<native::ItemsFilter> for ItemsFilter {
    fn from(value: native::ItemsFilter) -> Self {
        Self {
            query: value.query,
            include_deleted: value.include_deleted,
        }
    }
}

impl From<ItemsFilter> for native::ItemsFilter {
    fn from(value: ItemsFilter) -> Self {
        Self {
            query: value.query,
            include_deleted: value.include_deleted,
        }
    }
}

impl From<native::Page> for Page {
    fn from(value: native::Page) -> Self {
        Self {
            limit: value.limit,
            cursor: value.cursor,
        }
    }
}

impl From<Page> for native::Page {
    fn from(value: Page) -> Self {
        Self {
            limit: value.limit,
            cursor: value.cursor,
        }
    }
}

impl From<native::ItemSummary> for ItemSummary {
    fn from(value: native::ItemSummary) -> Self {
        Self {
            id: value.id,
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            deleted: value.deleted,
        }
    }
}

impl From<ItemSummary> for native::ItemSummary {
    fn from(value: ItemSummary) -> Self {
        Self {
            id: value.id,
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            deleted: value.deleted,
        }
    }
}

impl From<native::ItemCountsView> for ItemCountsFfi {
    fn from(value: native::ItemCountsView) -> Self {
        Self {
            all: value.all,
            trash: value.trash,
            by_type: value
                .by_type
                .into_iter()
                .map(|value| value.into())
                .collect(),
        }
    }
}

impl From<ItemCountsFfi> for native::ItemCountsView {
    fn from(value: ItemCountsFfi) -> Self {
        Self {
            all: value.all,
            trash: value.trash,
            by_type: value
                .by_type
                .into_iter()
                .map(|value| value.into())
                .collect(),
        }
    }
}

impl From<native::ItemTypeCount> for ItemTypeCount {
    fn from(value: native::ItemTypeCount) -> Self {
        Self {
            type_id: value.type_id,
            count: value.count,
        }
    }
}

impl From<ItemTypeCount> for native::ItemTypeCount {
    fn from(value: ItemTypeCount) -> Self {
        Self {
            type_id: value.type_id,
            count: value.count,
        }
    }
}

impl From<native::ItemPage> for ItemPage {
    fn from(value: native::ItemPage) -> Self {
        Self {
            items: value.items.into_iter().map(|value| value.into()).collect(),
            next_cursor: value.next_cursor,
            total_count: value.total_count,
            counts: value.counts.into(),
        }
    }
}

impl From<ItemPage> for native::ItemPage {
    fn from(value: ItemPage) -> Self {
        Self {
            items: value.items.into_iter().map(|value| value.into()).collect(),
            next_cursor: value.next_cursor,
            total_count: value.total_count,
            counts: value.counts.into(),
        }
    }
}

impl From<native::ItemDetail> for ItemDetail {
    fn from(value: native::ItemDetail) -> Self {
        Self {
            id: value.id,
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            payload_json: value.payload_json,
        }
    }
}

impl From<ItemDetail> for native::ItemDetail {
    fn from(value: ItemDetail) -> Self {
        Self {
            id: value.id,
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            payload_json: value.payload_json,
        }
    }
}

impl From<native::ItemCreate> for ItemCreate {
    fn from(value: native::ItemCreate) -> Self {
        Self {
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            payload_json: value.payload_json,
        }
    }
}

impl From<ItemCreate> for native::ItemCreate {
    fn from(value: ItemCreate) -> Self {
        Self {
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            payload_json: value.payload_json,
        }
    }
}

impl From<native::ItemUpdate> for ItemUpdate {
    fn from(value: native::ItemUpdate) -> Self {
        Self {
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            payload_json: value.payload_json,
        }
    }
}

impl From<ItemUpdate> for native::ItemUpdate {
    fn from(value: ItemUpdate) -> Self {
        Self {
            title: value.title,
            path: value.path,
            type_id: value.type_id,
            payload_json: value.payload_json,
        }
    }
}

impl From<native::ItemHistorySummary> for ItemHistorySummaryFfi {
    fn from(value: native::ItemHistorySummary) -> Self {
        Self {
            version: value.version,
            checksum: value.checksum,
            change_type: value.change_type,
            changed_by_name: value.changed_by_name,
            changed_by_email: value.changed_by_email,
            created_at: value.created_at,
            pending: value.pending,
        }
    }
}

impl From<ItemHistorySummaryFfi> for native::ItemHistorySummary {
    fn from(value: ItemHistorySummaryFfi) -> Self {
        Self {
            version: value.version,
            checksum: value.checksum,
            change_type: value.change_type,
            changed_by_name: value.changed_by_name,
            changed_by_email: value.changed_by_email,
            created_at: value.created_at,
            pending: value.pending,
        }
    }
}

impl From<native::ItemHistoryDetail> for ItemHistoryDetailFfi {
    fn from(value: native::ItemHistoryDetail) -> Self {
        Self {
            version: value.version,
            payload_json: value.payload_json,
        }
    }
}

impl From<ItemHistoryDetailFfi> for native::ItemHistoryDetail {
    fn from(value: ItemHistoryDetailFfi) -> Self {
        Self {
            version: value.version,
            payload_json: value.payload_json,
        }
    }
}

impl From<native::BackupImportOptions> for BackupImportOptions {
    fn from(value: native::BackupImportOptions) -> Self {
        Self {
            target_storage_id: value.target_storage_id,
        }
    }
}

impl From<BackupImportOptions> for native::BackupImportOptions {
    fn from(value: BackupImportOptions) -> Self {
        Self {
            target_storage_id: value.target_storage_id,
        }
    }
}

impl From<native::BackupExportReport> for BackupExportReport {
    fn from(value: native::BackupExportReport) -> Self {
        Self {
            path: value.path,
            storages_count: value.storages_count,
            vaults_count: value.vaults_count,
            items_count: value.items_count,
        }
    }
}

impl From<BackupExportReport> for native::BackupExportReport {
    fn from(value: BackupExportReport) -> Self {
        Self {
            path: value.path,
            storages_count: value.storages_count,
            vaults_count: value.vaults_count,
            items_count: value.items_count,
        }
    }
}

impl From<native::BackupImportReport> for BackupImportReport {
    fn from(value: native::BackupImportReport) -> Self {
        Self {
            imported_items: value.imported_items,
            skipped_existing: value.skipped_existing,
            skipped_missing_storage: value.skipped_missing_storage,
            skipped_missing_vault: value.skipped_missing_vault,
            skipped_deleted: value.skipped_deleted,
        }
    }
}

impl From<BackupImportReport> for native::BackupImportReport {
    fn from(value: BackupImportReport) -> Self {
        Self {
            imported_items: value.imported_items,
            skipped_existing: value.skipped_existing,
            skipped_missing_storage: value.skipped_missing_storage,
            skipped_missing_vault: value.skipped_missing_vault,
            skipped_deleted: value.skipped_deleted,
        }
    }
}

impl From<native::ApplePasswordsPreflight> for ApplePasswordsPreflightFfi {
    fn from(value: native::ApplePasswordsPreflight) -> Self {
        Self {
            total_rows: value.total_rows,
            importable_items: value.importable_items,
            duplicate_rows: value.duplicate_rows,
            invalid_rows: value.invalid_rows,
        }
    }
}

impl From<ApplePasswordsPreflightFfi> for native::ApplePasswordsPreflight {
    fn from(value: ApplePasswordsPreflightFfi) -> Self {
        Self {
            total_rows: value.total_rows,
            importable_items: value.importable_items,
            duplicate_rows: value.duplicate_rows,
            invalid_rows: value.invalid_rows,
        }
    }
}

impl From<native::ApplePasswordsImportReport> for ApplePasswordsImportReportFfi {
    fn from(value: native::ApplePasswordsImportReport) -> Self {
        Self {
            imported_items: value.imported_items,
            renamed_items: value.renamed_items,
            skipped_invalid: value.skipped_invalid,
        }
    }
}

impl From<ApplePasswordsImportReportFfi> for native::ApplePasswordsImportReport {
    fn from(value: ApplePasswordsImportReportFfi) -> Self {
        Self {
            imported_items: value.imported_items,
            renamed_items: value.renamed_items,
            skipped_invalid: value.skipped_invalid,
        }
    }
}

impl From<native::Snapshot> for SnapshotFfi {
    fn from(value: native::Snapshot) -> Self {
        Self {
            path: value.path,
            identity_path: value.identity_path,
            created_at: value.created_at,
            size_bytes: value.size_bytes,
        }
    }
}

impl From<SnapshotFfi> for native::Snapshot {
    fn from(value: SnapshotFfi) -> Self {
        Self {
            path: value.path,
            identity_path: value.identity_path,
            created_at: value.created_at,
            size_bytes: value.size_bytes,
        }
    }
}

impl From<native::SnapshotRestore> for SnapshotRestoreFfi {
    fn from(value: native::SnapshotRestore) -> Self {
        Self {
            restored_from: value.restored_from,
            replaced_saved_to: value.replaced_saved_to,
            identity_replaced: value.identity_replaced,
        }
    }
}

impl From<SnapshotRestoreFfi> for native::SnapshotRestore {
    fn from(value: SnapshotRestoreFfi) -> Self {
        Self {
            restored_from: value.restored_from,
            replaced_saved_to: value.replaced_saved_to,
            identity_replaced: value.identity_replaced,
        }
    }
}

impl From<native::VerifyProblem> for VerifyProblemFfi {
    fn from(value: native::VerifyProblem) -> Self {
        Self {
            kind: value.kind,
            vault_name: value.vault_name,
            item_path: value.item_path,
            detail: value.detail,
        }
    }
}

impl From<VerifyProblemFfi> for native::VerifyProblem {
    fn from(value: VerifyProblemFfi) -> Self {
        Self {
            kind: value.kind,
            vault_name: value.vault_name,
            item_path: value.item_path,
            detail: value.detail,
        }
    }
}

impl From<native::VerifyReport> for VerifyReportFfi {
    fn from(value: native::VerifyReport) -> Self {
        Self {
            database_ok: value.database_ok,
            vaults_checked: value.vaults_checked,
            vaults_skipped: value.vaults_skipped,
            items_checked: value.items_checked,
            items_ok: value.items_ok,
            problems: value
                .problems
                .into_iter()
                .map(|value| value.into())
                .collect(),
        }
    }
}

impl From<VerifyReportFfi> for native::VerifyReport {
    fn from(value: VerifyReportFfi) -> Self {
        Self {
            database_ok: value.database_ok,
            vaults_checked: value.vaults_checked,
            vaults_skipped: value.vaults_skipped,
            items_checked: value.items_checked,
            items_ok: value.items_ok,
            problems: value
                .problems
                .into_iter()
                .map(|value| value.into())
                .collect(),
        }
    }
}

impl From<native::Retention> for RetentionFfi {
    fn from(value: native::Retention) -> Self {
        Self {
            max_count: value.max_count,
            max_age_days: value.max_age_days,
        }
    }
}

impl From<RetentionFfi> for native::Retention {
    fn from(value: RetentionFfi) -> Self {
        Self {
            max_count: value.max_count,
            max_age_days: value.max_age_days,
        }
    }
}

impl From<native::StorageSummary> for StorageSummaryFfi {
    fn from(value: native::StorageSummary) -> Self {
        Self {
            id: value.id,
            name: value.name,
            kind: value.kind,
        }
    }
}

impl From<StorageSummaryFfi> for native::StorageSummary {
    fn from(value: StorageSummaryFfi) -> Self {
        Self {
            id: value.id,
            name: value.name,
            kind: value.kind,
        }
    }
}

impl From<native::AppStatus> for AppStatusFfi {
    fn from(value: native::AppStatus) -> Self {
        Self {
            initialized: value.initialized,
            locked: value.locked,
            storages_count: value.storages_count,
            has_local_vault: value.has_local_vault,
        }
    }
}

impl From<AppStatusFfi> for native::AppStatus {
    fn from(value: AppStatusFfi) -> Self {
        Self {
            initialized: value.initialized,
            locked: value.locked,
            storages_count: value.storages_count,
            has_local_vault: value.has_local_vault,
        }
    }
}

impl From<native::HardwareKey> for HardwareKeyFfi {
    fn from(value: native::HardwareKey) -> Self {
        Self {
            label: value.label,
            credential_id: value.credential_id,
            enrolled_at: value.enrolled_at,
        }
    }
}

impl From<HardwareKeyFfi> for native::HardwareKey {
    fn from(value: HardwareKeyFfi) -> Self {
        Self {
            label: value.label,
            credential_id: value.credential_id,
            enrolled_at: value.enrolled_at,
        }
    }
}

impl From<native::RememberedUnlock> for RememberedUnlockFfi {
    fn from(value: native::RememberedUnlock) -> Self {
        Self {
            armed: value.armed,
            source: value.source,
            hardware_keys: value
                .hardware_keys
                .into_iter()
                .map(|value| value.into())
                .collect(),
            hardware_supported: value.hardware_supported,
        }
    }
}

impl From<RememberedUnlockFfi> for native::RememberedUnlock {
    fn from(value: RememberedUnlockFfi) -> Self {
        Self {
            armed: value.armed,
            source: value.source,
            hardware_keys: value
                .hardware_keys
                .into_iter()
                .map(|value| value.into())
                .collect(),
            hardware_supported: value.hardware_supported,
        }
    }
}

impl From<native::LocalSyncOutcome> for SyncOutcomeFfi {
    fn from(value: native::LocalSyncOutcome) -> Self {
        Self {
            status: value.status,
            vaults_reconciled: value.vaults_reconciled,
            pages_committed: value.pages_committed,
            changes_committed: value.changes_committed,
        }
    }
}

impl From<SyncOutcomeFfi> for native::LocalSyncOutcome {
    fn from(value: SyncOutcomeFfi) -> Self {
        Self {
            status: value.status,
            vaults_reconciled: value.vaults_reconciled,
            pages_committed: value.pages_committed,
            changes_committed: value.changes_committed,
        }
    }
}
