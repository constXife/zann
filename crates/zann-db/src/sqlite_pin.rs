//! Connection-local write guards: every mutation checks the pool's original
//! logical identity under SQLite's writer reservation, not before acquiring it.
use crate::LocalDatabaseInstanceId;
use sqlx_core::query::query;
use sqlx_sqlite::SqliteConnection;

pub(crate) async fn install(
    connection: &mut SqliteConnection,
    expected: LocalDatabaseInstanceId,
) -> Result<(), sqlx_core::Error> {
    let literal = expected
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    // Fixed trusted schema names; no application input is interpolated.
    for table in [
        "storages",
        "local_vaults",
        "items_cache",
        "pending_changes",
        "item_history",
        "sync_cursors",
        "metadata",
        "local_database_identity",
    ] {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            let predicate = if table == "local_database_identity" {
                "1".to_owned() // Identity rotation belongs to explicit maintenance.
            } else {
                format!("(SELECT instance_uuid FROM main.local_database_identity WHERE singleton = 1) IS NOT X'{literal}'")
            };
            query(&format!("CREATE TEMP TRIGGER zann_pin_{table}_{action} BEFORE {action} ON main.{table} WHEN {predicate} BEGIN SELECT RAISE(ABORT, 'local database instance changed'); END"))
                .execute(&mut *connection).await?;
        }
    }
    Ok(())
}
