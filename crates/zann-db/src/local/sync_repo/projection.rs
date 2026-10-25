use super::*;

pub(super) async fn ensure_item_expectation(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    item_id: Uuid,
    expectation: &LocalItemExpectation,
) -> Result<(), LocalSyncError> {
    let matches = match expectation {
        LocalItemExpectation::Absent => {
            query!(r#"SELECT 1 FROM items_cache WHERE id = ?1"#, item_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(LocalSyncError::Database)?
                .is_none()
        }
        LocalItemExpectation::Exact(proof) => {
            ensure_item_projection_bounded(tx, item_id).await?;
            query!(
                r#"
                SELECT 1
                FROM items_cache
                WHERE id = ?1
                  AND storage_id = ?2
                  AND vault_id = ?3
                  AND path = ?4
                  AND name = ?5
                  AND type_id = ?6
                  AND payload_enc = ?7
                  AND checksum = ?8
                  AND cache_key_fp IS ?9
                  AND version = ?10
                  AND deleted_at IS ?11
                  AND updated_at = ?12
                  AND sync_status = ?13
                "#,
                proof.id,
                scope.storage_id,
                scope.vault_id,
                proof.path.as_str(),
                proof.name.as_str(),
                proof.type_id.as_str(),
                &proof.payload_enc,
                proof.checksum.as_str(),
                proof.cache_key_fp.as_deref(),
                proof.version,
                proof.deleted_at,
                proof.updated_at,
                proof.sync_status.as_i32()
            )
            .fetch_optional(&mut **tx)
            .await
            .map_err(LocalSyncError::Database)?
            .is_some()
        }
    };
    if !matches {
        return Err(LocalSyncError::StaleItem { item_id });
    }
    Ok(())
}

pub(super) async fn ensure_item_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(path) = 'text'
                THEN octet_length(path) BETWEEN 1 AND ?2 ELSE 0 END
            AND CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?3 ELSE 0 END
            AND CASE WHEN typeof(type_id) = 'text'
                THEN octet_length(type_id) BETWEEN 1 AND ?4 ELSE 0 END
            AND CASE WHEN typeof(payload_enc) = 'blob'
                THEN length(payload_enc) <= ?5 ELSE 0 END
            AND CASE WHEN typeof(checksum) = 'text'
                THEN octet_length(checksum) BETWEEN 1 AND ?6 ELSE 0 END
            AND (cache_key_fp IS NULL OR CASE WHEN typeof(cache_key_fp) = 'text'
                THEN octet_length(cache_key_fp) = ?7 ELSE 0 END)
            AND CASE WHEN typeof(version) = 'integer'
                THEN version >= 1 ELSE 0 END
            AND (deleted_at IS NULL OR CASE WHEN typeof(deleted_at) = 'text'
                THEN octet_length(deleted_at) BETWEEN 1 AND ?8 ELSE 0 END)
            AND CASE WHEN typeof(updated_at) = 'text'
                THEN octet_length(updated_at) BETWEEN 1 AND ?8 ELSE 0 END
            AND CASE WHEN typeof(sync_status) = 'integer'
                THEN sync_status IN (1, 2, 3, 4, 5, 6) ELSE 0 END
        THEN 1 ELSE 0 END AS valid
        FROM items_cache
        WHERE id = ?1
        "#,
        item_id,
        MAX_ITEM_PATH_LEN as i64,
        MAX_ITEM_NAME_LEN as i64,
        MAX_TYPE_ID_BYTES as i64,
        MAX_ITEM_CIPHERTEXT_BYTES as i64,
        MAX_CHECKSUM_BYTES as i64,
        CACHE_KEY_FINGERPRINT_BYTES as i64,
        MAX_TIMESTAMP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let is_valid = match valid {
        Some(row) => {
            row.try_get::<i64, _>("valid")
                .map_err(LocalSyncError::Database)?
                == 1
        }
        None => false,
    };
    if !is_valid {
        return Err(LocalSyncError::StaleItem { item_id });
    }
    Ok(())
}

pub(super) async fn ensure_no_pending_for_item(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    item_id: Uuid,
) -> Result<(), LocalSyncError> {
    ensure_pending_identifiers_bounded(tx).await?;
    let row = query!(
        r#"
        SELECT id as "id"
        FROM pending_changes
        WHERE storage_id = ?1 AND item_id = ?2
        LIMIT 1
        "#,
        scope.storage_id,
        item_id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if let Some(row) = row {
        let pending_id = row.try_get("id").map_err(LocalSyncError::Database)?;
        return Err(LocalSyncError::StalePending { pending_id });
    }
    Ok(())
}

pub(super) async fn ensure_pending_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM pending_changes
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1
            WHEN typeof(item_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(item_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return invalid("local pending identifiers are corrupt");
    }
    Ok(())
}

pub(super) async fn ensure_pending_proof(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    proof: &LocalPendingProof,
) -> Result<(), LocalSyncError> {
    ensure_pending_identifiers_bounded(tx).await?;
    ensure_pending_projection_bounded(tx, proof.id).await?;
    let row = query!(
        r#"
        SELECT 1
        FROM pending_changes
        WHERE id = ?1
          AND storage_id = ?2
          AND vault_id = ?3
          AND item_id = ?4
          AND operation = ?5
          AND payload_enc IS ?6
          AND checksum IS ?7
          AND path IS ?8
          AND name IS ?9
          AND type_id IS ?10
          AND base_seq IS ?11
          AND created_at = ?12
        "#,
        proof.id,
        scope.storage_id,
        scope.vault_id,
        proof.item_id,
        proof.operation.as_i32(),
        proof.payload_enc.as_deref(),
        proof.checksum.as_deref(),
        proof.path.as_deref(),
        proof.name.as_deref(),
        proof.type_id.as_deref(),
        proof.base_seq,
        proof.created_at
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if row.is_none() {
        return Err(LocalSyncError::StalePending {
            pending_id: proof.id,
        });
    }
    Ok(())
}

pub(super) async fn ensure_pending_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    pending_id: Uuid,
) -> Result<(), LocalSyncError> {
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(storage_id) IN ('blob', 'text')
                THEN octet_length(storage_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(vault_id) IN ('blob', 'text')
                THEN octet_length(vault_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(item_id) IN ('blob', 'text')
                THEN octet_length(item_id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(operation) = 'integer'
                THEN operation IN (1, 2, 3, 4) ELSE 0 END
            AND (payload_enc IS NULL OR CASE WHEN typeof(payload_enc) = 'blob'
                THEN length(payload_enc) <= ?2 ELSE 0 END)
            AND (checksum IS NULL OR CASE WHEN typeof(checksum) = 'text'
                THEN octet_length(checksum) BETWEEN 1 AND ?3 ELSE 0 END)
            AND (path IS NULL OR CASE WHEN typeof(path) = 'text'
                THEN octet_length(path) BETWEEN 1 AND ?4 ELSE 0 END)
            AND (name IS NULL OR CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?5 ELSE 0 END)
            AND (type_id IS NULL OR CASE WHEN typeof(type_id) = 'text'
                THEN octet_length(type_id) BETWEEN 1 AND ?6 ELSE 0 END)
            AND CASE
                WHEN base_seq IS NULL THEN 1
                WHEN typeof(base_seq) = 'integer' THEN base_seq >= 1
                ELSE 0
            END
            AND CASE WHEN typeof(created_at) = 'text'
                THEN octet_length(created_at) BETWEEN 1 AND ?7 ELSE 0 END
        THEN 1 ELSE 0 END AS valid
        FROM pending_changes
        WHERE id = ?1
        "#,
        pending_id,
        MAX_ITEM_CIPHERTEXT_BYTES as i64,
        MAX_CHECKSUM_BYTES as i64,
        MAX_ITEM_PATH_LEN as i64,
        MAX_ITEM_NAME_LEN as i64,
        MAX_TYPE_ID_BYTES as i64,
        MAX_TIMESTAMP_BYTES as i64
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let is_valid = match valid {
        Some(row) => {
            row.try_get::<i64, _>("valid")
                .map_err(LocalSyncError::Database)?
                == 1
        }
        None => false,
    };
    if !is_valid {
        return Err(LocalSyncError::StalePending { pending_id });
    }
    Ok(())
}

pub(super) async fn apply_item_projection(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    expected_item_id: Uuid,
    expectation: &LocalItemExpectation,
    item: &LocalItem,
) -> Result<(), LocalSyncError> {
    match expectation {
        LocalItemExpectation::Absent => {
            let result = query!(
                r#"
                INSERT INTO items_cache (
                    id, storage_id, vault_id, path, name, type_id, payload_enc, checksum,
                    cache_key_fp, version, deleted_at, updated_at, sync_status
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
                item.id,
                item.storage_id,
                item.vault_id,
                item.path.as_str(),
                item.name.as_str(),
                item.type_id.as_str(),
                &item.payload_enc,
                item.checksum.as_str(),
                item.cache_key_fp.as_deref(),
                item.version,
                item.deleted_at,
                item.updated_at,
                item.sync_status.as_i32()
            )
            .execute(&mut **tx)
            .await;
            if let Err(error) = result {
                return Err(LocalSyncError::Database(error));
            }
        }
        LocalItemExpectation::Exact(proof) => {
            let result = query!(
                r#"
                UPDATE items_cache
                SET path = ?14,
                    name = ?15,
                    type_id = ?16,
                    payload_enc = ?17,
                    checksum = ?18,
                    cache_key_fp = ?19,
                    version = ?20,
                    deleted_at = ?21,
                    updated_at = ?22,
                    sync_status = ?23
                WHERE id = ?1
                  AND storage_id = ?2
                  AND vault_id = ?3
                  AND path = ?4
                  AND name = ?5
                  AND type_id = ?6
                  AND payload_enc = ?7
                  AND checksum = ?8
                  AND cache_key_fp IS ?9
                  AND version = ?10
                  AND deleted_at IS ?11
                  AND updated_at = ?12
                  AND sync_status = ?13
                "#,
                proof.id,
                scope.storage_id,
                scope.vault_id,
                proof.path.as_str(),
                proof.name.as_str(),
                proof.type_id.as_str(),
                &proof.payload_enc,
                proof.checksum.as_str(),
                proof.cache_key_fp.as_deref(),
                proof.version,
                proof.deleted_at,
                proof.updated_at,
                proof.sync_status.as_i32(),
                item.path.as_str(),
                item.name.as_str(),
                item.type_id.as_str(),
                &item.payload_enc,
                item.checksum.as_str(),
                item.cache_key_fp.as_deref(),
                item.version,
                item.deleted_at,
                item.updated_at,
                item.sync_status.as_i32()
            )
            .execute(&mut **tx)
            .await
            .map_err(LocalSyncError::Database)?;
            if result.rows_affected() != 1 {
                return Err(LocalSyncError::StaleItem {
                    item_id: expected_item_id,
                });
            }
        }
    }
    Ok(())
}

pub(super) async fn delete_pending_exact(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    proof: &LocalPendingProof,
) -> Result<(), LocalSyncError> {
    let result = query!(
        r#"
        DELETE FROM pending_changes
        WHERE id = ?1
          AND storage_id = ?2
          AND vault_id = ?3
          AND item_id = ?4
          AND operation = ?5
          AND payload_enc IS ?6
          AND checksum IS ?7
          AND path IS ?8
          AND name IS ?9
          AND type_id IS ?10
          AND base_seq IS ?11
          AND created_at = ?12
        "#,
        proof.id,
        scope.storage_id,
        scope.vault_id,
        proof.item_id,
        proof.operation.as_i32(),
        proof.payload_enc.as_deref(),
        proof.checksum.as_deref(),
        proof.path.as_deref(),
        proof.name.as_deref(),
        proof.type_id.as_deref(),
        proof.base_seq,
        proof.created_at
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if result.rows_affected() != 1 {
        return Err(LocalSyncError::StalePending {
            pending_id: proof.id,
        });
    }
    Ok(())
}

pub(super) async fn replace_history(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
    change: &PullChange,
) -> Result<(), LocalSyncError> {
    ensure_history_identifiers_bounded(tx).await?;
    let corrupt_filter = query!(
        r#"
        SELECT 1
        FROM item_history
        WHERE storage_id = ?1 AND vault_id = ?2 AND item_id = ?3
          AND CASE
            WHEN typeof(source) != 'integer' THEN 1
            WHEN source NOT IN (1, 2, 3) THEN 1
            WHEN typeof(sync_status) != 'integer' THEN 1
            WHEN sync_status NOT IN (1, 2, 3) THEN 1
            ELSE 0
          END
        LIMIT 1
        "#,
        scope.storage_id,
        scope.vault_id,
        change.item.id
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt_filter.is_some() {
        return invalid("local history authority fields are corrupt");
    }
    query!(
        r#"
        DELETE FROM item_history
        WHERE storage_id = ?1 AND vault_id = ?2 AND item_id = ?3
          AND source = ?4 AND sync_status = ?5
        "#,
        scope.storage_id,
        scope.vault_id,
        change.item.id,
        HistorySource::Server.as_i32(),
        HistorySyncStatus::Confirmed.as_i32()
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;

    for entry in &change.history {
        query!(
            r#"
            INSERT INTO item_history (
                id, storage_id, vault_id, item_id, payload_enc, checksum, version,
                change_type, changed_by_email, changed_by_name, changed_by_device_id,
                changed_by_device_name, source, sync_status, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
            entry.id,
            entry.storage_id,
            entry.vault_id,
            entry.item_id,
            &entry.payload_enc,
            entry.checksum.as_str(),
            entry.version,
            entry.change_type.as_i32(),
            entry.changed_by_email.as_str(),
            entry.changed_by_name.as_deref(),
            entry.changed_by_device_id,
            entry.changed_by_device_name.as_deref(),
            entry.source.as_i32(),
            entry.sync_status.as_i32(),
            entry.created_at
        )
        .execute(&mut **tx)
        .await
        .map_err(LocalSyncError::Database)?;
    }
    Ok(())
}

pub(super) async fn ensure_history_identifiers_bounded(
    tx: &mut Transaction<'static, Sqlite>,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM item_history
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(storage_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(storage_id) NOT IN (16, 36) THEN 1
            WHEN typeof(vault_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(vault_id) NOT IN (16, 36) THEN 1
            WHEN typeof(item_id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(item_id) NOT IN (16, 36) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return invalid("local history identifiers are corrupt");
    }
    Ok(())
}
