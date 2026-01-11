macro_rules! query {
    ($sql:expr $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut q = sqlx_core::query::query::<sqlx_sqlite::Sqlite>($sql);
        $(q = q.bind($arg);)*
        q
    }};
}

macro_rules! query_as {
    ($ty:ty, $sql:expr $(, $arg:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut q = sqlx_core::query_as::query_as::<sqlx_sqlite::Sqlite, $ty>($sql);
        $(q = q.bind($arg);)*
        q
    }};
}

mod item_history_repo;
mod item_repo;
mod metadata_repo;
mod models;
mod pending_change_repo;
mod storage_repo;
mod sync_cursor_repo;
mod vault_repo;

pub use item_history_repo::LocalItemHistoryRepo;
pub use item_repo::LocalItemRepo;
pub use metadata_repo::MetadataRepo;
pub use models::{
    LocalItem, LocalItemHistory, LocalPendingChange, LocalStorage, LocalSyncCursor, LocalVault,
};
pub use pending_change_repo::PendingChangeRepo;
pub use storage_repo::LocalStorageRepo;
pub use sync_cursor_repo::SyncCursorRepo;
pub use vault_repo::LocalVaultRepo;
