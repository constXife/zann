use super::*;

pub(super) async fn ensure_checkpoint(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    expected_cursor: Option<&str>,
    expected_last_seq: Option<i64>,
) -> Result<(), LocalSyncError> {
    ensure_checkpoint_projection_bounded(tx, scope).await?;
    // Compare both checkpoint fields inside SQLite. A missing row is equivalent
    // only to the all-NULL initial checkpoint.
    let matches = query!(
        r#"
        SELECT 1
        WHERE EXISTS (
            SELECT 1
            FROM sync_cursors
            WHERE storage_id = ?1
              AND vault_id = ?2
              AND cursor IS ?3
              AND last_seq IS ?4
        )
        OR (
            ?3 IS NULL
            AND ?4 IS NULL
            AND NOT EXISTS (
                SELECT 1
                FROM sync_cursors
                WHERE storage_id = ?1 AND vault_id = ?2
            )
        )
        "#,
        scope.storage_id,
        scope.vault_id,
        expected_cursor,
        expected_last_seq
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .is_some();
    if !matches {
        return Err(LocalSyncError::StaleCursor { scope });
    }
    Ok(())
}

pub(super) async fn ensure_checkpoint_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    ensure_checkpoint_identifiers_bounded(tx, scope).await?;
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
            AND (cursor IS NULL OR CASE WHEN typeof(cursor) = 'text'
                THEN octet_length(cursor) BETWEEN 1 AND ?3 ELSE 0 END)
            AND CASE
                WHEN last_seq IS NULL THEN 1
                WHEN typeof(last_seq) = 'integer' THEN last_seq >= 1
                ELSE 0
            END
            AND (last_sync_at IS NULL OR CASE WHEN typeof(last_sync_at) = 'text'
                THEN octet_length(last_sync_at) BETWEEN 1 AND ?4 ELSE 0 END)
        THEN 1 ELSE 0 END AS valid
        FROM sync_cursors
        WHERE storage_id = ?1 AND vault_id = ?2
        "#,
        scope.storage_id,
        scope.vault_id,
        MAX_CURSOR_BYTES as i64,
        MAX_TIMESTAMP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if let Some(row) = valid {
        let is_valid = row
            .try_get::<i64, _>("valid")
            .map_err(LocalSyncError::Database)?
            == 1;
        if !is_valid {
            return Err(LocalSyncError::StaleCursor { scope });
        }
    }
    Ok(())
}

pub(super) async fn ensure_checkpoint_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM sync_cursors
        WHERE CASE
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return Err(LocalSyncError::StaleCursor { scope });
    }
    Ok(())
}

pub(super) async fn ensure_vault_cache_key_fingerprint(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    expected_cache_key_fp: &str,
) -> Result<(), LocalSyncError> {
    let bounded = bounded_vault_preflight(tx, scope.storage_id, Some(scope.vault_id))
        .await
        .map_err(LocalSyncError::Database)?;
    if bounded != Some(true) {
        return Err(LocalSyncError::StaleVaultKey { scope });
    }
    let matches = query!(
        r#"
        SELECT 1
        FROM local_vaults
        WHERE storage_id = ?1
          AND id = ?2
          AND cache_key_fp = ?3
        "#,
        scope.storage_id,
        scope.vault_id,
        expected_cache_key_fp
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .is_some();
    if !matches {
        return Err(LocalSyncError::StaleVaultKey { scope });
    }
    Ok(())
}

pub(super) async fn publish_checkpoint(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
) -> Result<(), LocalSyncError> {
    let result = query!(
        r#"
        INSERT INTO sync_cursors (storage_id, vault_id, cursor, last_sync_at, last_seq)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(storage_id, vault_id) DO UPDATE SET
            cursor = excluded.cursor,
            last_sync_at = excluded.last_sync_at,
            last_seq = excluded.last_seq
        WHERE sync_cursors.cursor IS ?6
          AND sync_cursors.last_seq IS ?7
        "#,
        page.scope.storage_id,
        page.scope.vault_id,
        page.next_cursor.as_str(),
        page.committed_at,
        page.next_last_seq,
        page.expected_cursor.as_deref(),
        page.expected_last_seq
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if result.rows_affected() != 1 {
        return Err(LocalSyncError::StaleCursor { scope: page.scope });
    }
    Ok(())
}
