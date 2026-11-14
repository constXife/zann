//! Indexed, cardinality/byte-bounded login pages, without per-item lookups.
use super::*;

impl LocalItemRepo<'_> {
    pub async fn browser_login_page(
        &self,
        storage: Uuid,
        vault: Uuid,
        after: Option<Uuid>,
    ) -> Result<Vec<LocalItem>, sqlx_core::Error> {
        let columns = format!(
            r#"
            SELECT id, storage_id, vault_id,
                CASE WHEN octet_length(path) <= {MAX_ITEM_PATH_BYTES} THEN path END AS path,
                CASE WHEN octet_length(name) <= {MAX_ITEM_NAME_BYTES} THEN name END AS name,
                type_id,
                CASE WHEN octet_length(payload_enc) <= {MAX_ITEM_CIPHERTEXT_BYTES} THEN payload_enc END AS payload_enc,
                CASE WHEN octet_length(checksum) <= {MAX_ITEM_CHECKSUM_BYTES} THEN checksum END AS checksum,
                CASE WHEN cache_key_fp IS NULL OR octet_length(cache_key_fp) = {CACHE_KEY_FINGERPRINT_BYTES} THEN cache_key_fp ELSE 'invalid' END AS cache_key_fp,
                version, deleted_at,
                CASE WHEN octet_length(updated_at) <= {MAX_TIMESTAMP_BYTES} THEN updated_at END AS updated_at,
                sync_status,
                CASE WHEN metadata IS NULL OR octet_length(metadata) <= 65536 THEN metadata ELSE 'invalid' END AS metadata
            FROM items_cache WHERE storage_id = "#
        );
        let mut query = sqlx_core::query_builder::QueryBuilder::<sqlx_sqlite::Sqlite>::new(columns);
        query
            .push_bind(storage)
            .push(" AND vault_id = ")
            .push_bind(vault)
            .push(" AND type_id = 'login' AND deleted_at IS NULL");
        if let Some(after) = after {
            query.push(" AND id > ").push_bind(after);
        }
        query
            .push(" ORDER BY id LIMIT ")
            .push_bind(i64::from(zann_core::BROWSER_PAGE_LIMIT) + 1);
        let rows = query
            .build_query_as::<LocalItem>()
            .fetch_all(self.pool)
            .await?;
        if rows.iter().any(|row| {
            row.cache_key_fp
                .as_ref()
                .is_some_and(|fp| fp.len() != CACHE_KEY_FINGERPRINT_BYTES as usize)
        }) {
            return Err(sqlx_core::Error::Protocol(
                "browser cache-key fingerprint bound".into(),
            ));
        }
        Ok(rows)
    }
}
