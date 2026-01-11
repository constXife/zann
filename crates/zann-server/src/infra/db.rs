use sqlx_core::query::query;
use sqlx_postgres::{PgConnection, Postgres};

use crate::settings::DbTxIsolation;

pub async fn apply_tx_isolation(
    conn: &mut PgConnection,
    isolation: DbTxIsolation,
) -> Result<(), sqlx_core::Error> {
    match isolation {
        DbTxIsolation::ReadCommitted => {
            query::<Postgres>("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        }
        DbTxIsolation::RepeatableRead => {
            query::<Postgres>("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        }
        DbTxIsolation::Serializable => {
            query::<Postgres>("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        }
    }
    .execute(&mut *conn)
    .await
    .map(|_| ())
}
