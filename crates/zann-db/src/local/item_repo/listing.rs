use super::*;
use sqlx_core::query_builder::QueryBuilder;
use sqlx_sqlite::Sqlite;
use zann_core::{ItemCounts, UpdatedRange};

// Matches the expression index in 0014_vault_list_timestamp.sql.
const UPDATED: &str = "CASE typeof(updated_at) WHEN 'integer' THEN strftime('%Y-%m-%dT%H:%M:%S', updated_at, 'unixepoch') || '+00:00' ELSE updated_at END";

impl LocalItemRepo<'_> {
    pub(crate) fn scoped_list(
        mut query: QueryBuilder<'static, Sqlite>,
        storage: Uuid,
        vault: Uuid,
        updated: Option<UpdatedRange>,
    ) -> QueryBuilder<'static, Sqlite> {
        query
            .push(" FROM items_cache AS i WHERE storage_id = ")
            .push_bind(storage)
            .push(" AND vault_id = ")
            .push_bind(vault);
        if let Some(range) = updated {
            query
                .push(" AND ")
                .push(UPDATED)
                .push(" >= ")
                .push_bind(range.start())
                .push(" AND ")
                .push(UPDATED)
                .push(" < ")
                .push_bind(range.end());
        }
        query
    }

    pub(crate) fn order_list(query: &mut QueryBuilder<'_, Sqlite>) {
        query
            .push(" ORDER BY ")
            .push(UPDATED)
            .push(" DESC, id DESC");
    }

    pub async fn list_by_vault_paged(
        &self,
        storage: Uuid,
        vault: Uuid,
        updated: Option<UpdatedRange>,
        include_deleted: bool,
        limit: i64,
        cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> Result<Vec<LocalItem>, sqlx_core::Error> {
        let mut q = Self::scoped_list(QueryBuilder::new("SELECT i.*"), storage, vault, updated);
        if !include_deleted {
            q.push(" AND deleted_at IS NULL");
        }
        if let Some((ts, id)) = cursor {
            q.push(" AND (")
                .push(UPDATED)
                .push(", id) < (")
                .push_bind(ts)
                .push(", ")
                .push_bind(id)
                .push(")");
        }
        Self::order_list(&mut q);
        q.push(" LIMIT ")
            .push_bind(limit)
            .build_query_as()
            .fetch_all(self.pool)
            .await
    }

    pub(crate) async fn list_counts(
        &self,
        storage: Uuid,
        vault: Uuid,
        updated: Option<UpdatedRange>,
    ) -> Result<ItemCounts, sqlx_core::Error> {
        let mut q = Self::scoped_list(
            QueryBuilder::new("SELECT type_id, deleted_at IS NOT NULL, COUNT(*)"),
            storage,
            vault,
            updated,
        );
        let rows = q
            .push(" GROUP BY type_id, deleted_at IS NOT NULL")
            .build_query_as::<(String, bool, i64)>()
            .fetch_all(self.pool)
            .await?;
        let mut counts = ItemCounts::default();
        for (kind, deleted, count) in rows {
            if deleted {
                counts.trash += count as usize;
            } else {
                counts.all += count as usize;
                counts.by_type.insert(kind, count as usize);
            }
        }
        Ok(counts)
    }
}
