use super::*;

pub(super) async fn finish_transaction<T>(
    tx: Transaction<'static, Sqlite>,
    result: Result<T, LocalSyncError>,
) -> Result<T, LocalSyncError> {
    match result {
        Ok(receipt) => {
            // A COMMIT transport/IO error does not prove whether SQLite made
            // the transaction durable. Expose ambiguity explicitly so callers
            // reconcile state instead of replaying a destructive plan.
            tx.commit()
                .await
                .map_err(|_| LocalSyncError::CommitOutcomeUnknown)?;
            Ok(receipt)
        }
        Err(error) => {
            tx.rollback().await.map_err(LocalSyncError::Database)?;
            Err(error)
        }
    }
}

pub(super) async fn commit_push_in(
    tx: &mut Transaction<'static, Sqlite>,
    commit: &PushCommit,
) -> Result<PushReceipt, LocalSyncError> {
    ensure_materialized_scope(tx, commit.scope).await?;
    ensure_checkpoint(
        tx,
        commit.scope,
        commit.expected_cursor.as_deref(),
        commit.expected_last_seq,
    )
    .await?;

    // Prove the whole response against one writer-serialized snapshot before
    // applying any outcome. Mutations still repeat the CAS in their WHERE
    // clauses so this invariant remains visible in the SQL itself.
    for outcome in &commit.outcomes {
        match &outcome.kind {
            PushOutcomeKind::Applied {
                pending,
                expected_item,
                ..
            } => {
                ensure_item_expectation(tx, commit.scope, pending.item_id, expected_item).await?;
                ensure_pending_proof(tx, commit.scope, pending).await?;
            }
            PushOutcomeKind::Conflict => return invalid("conflicted push batch is fail-closed"),
        }
    }

    let mut applied = 0;
    for outcome in &commit.outcomes {
        match &outcome.kind {
            PushOutcomeKind::Applied {
                pending,
                expected_item,
                item,
            } => {
                apply_item_projection(tx, commit.scope, pending.item_id, expected_item, item)
                    .await?;
                delete_pending_exact(tx, commit.scope, pending).await?;
                applied += 1;
            }
            PushOutcomeKind::Conflict => return invalid("conflicted push batch is fail-closed"),
        }
    }

    Ok(PushReceipt {
        applied,
        pending_deleted: commit.outcomes.len(),
        server_head_hint: commit.server_head_hint.clone(),
        last_seq: commit.expected_last_seq,
    })
}

pub(super) async fn commit_push_leased_in(
    tx: &mut Transaction<'static, Sqlite>,
    commit: &PushCommit,
    expected_storage: &LocalStorageProof,
    generation: &LocalSyncGenerationProof,
) -> Result<PushReceipt, LocalSyncError> {
    ensure_storage_proof(tx, expected_storage).await?;
    ensure_single_remote_storage(tx, expected_storage.id).await?;
    ensure_bound_generation_and_advance(tx, expected_storage.id, generation).await?;
    commit_push_in(tx, commit).await
}

pub(super) async fn commit_pull_in(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
) -> Result<PullReceipt, LocalSyncError> {
    ensure_materialized_scope(tx, page.scope).await?;
    ensure_vault_cache_key_fingerprint(tx, page.scope, page.expected_vault_cache_key_fp.as_str())
        .await?;
    ensure_checkpoint(
        tx,
        page.scope,
        page.expected_cursor.as_deref(),
        page.expected_last_seq,
    )
    .await?;

    for change in &page.changes {
        ensure_item_expectation(tx, page.scope, change.item.id, &change.expected_item).await?;
        ensure_no_pending_for_item(tx, page.scope, change.item.id).await?;
    }

    let mut history_entries = 0;
    for change in &page.changes {
        apply_item_projection(
            tx,
            page.scope,
            change.item.id,
            &change.expected_item,
            &change.item,
        )
        .await?;
        replace_history(tx, page.scope, change).await?;
        history_entries += change.history.len();
    }

    publish_checkpoint(tx, page).await?;

    Ok(PullReceipt {
        items: page.changes.len(),
        history_entries,
        cursor: page.next_cursor.clone(),
        last_seq: page.next_last_seq,
    })
}

pub(super) async fn commit_pull_bound_in(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
    expected_storage: &LocalStorageProof,
) -> Result<PullReceipt, LocalSyncError> {
    ensure_storage_proof(tx, expected_storage).await?;
    ensure_single_remote_storage(tx, expected_storage.id).await?;
    commit_pull_in(tx, page).await
}

pub(super) async fn commit_pull_leased_in(
    tx: &mut Transaction<'static, Sqlite>,
    page: &PullPage,
    expected_storage: &LocalStorageProof,
    generation: &LocalSyncGenerationProof,
) -> Result<PullReceipt, LocalSyncError> {
    ensure_storage_proof(tx, expected_storage).await?;
    ensure_single_remote_storage(tx, expected_storage.id).await?;
    ensure_bound_generation_and_advance(tx, expected_storage.id, generation).await?;
    commit_pull_in(tx, page).await
}

pub(super) async fn reset_projection_in(
    tx: &mut Transaction<'static, Sqlite>,
    reset: &ResetProjection,
) -> Result<ResetReceipt, LocalSyncError> {
    ensure_storage_proof(tx, &reset.expected_storage).await?;
    ensure_vault_references_are_storage_scoped(tx, reset.storage_id).await?;

    let pending_count: i64 = query!(
        r#"SELECT COUNT(*) AS count FROM pending_changes WHERE storage_id = ?1"#,
        reset.storage_id
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .try_get("count")
    .map_err(LocalSyncError::Database)?;
    let pending_count = u64::try_from(pending_count).map_err(|_| LocalSyncError::InvalidPlan {
        reason: "pending row count is outside the supported range",
    })?;
    if pending_count != 0 {
        return Err(LocalSyncError::PendingChangesPresent {
            storage_id: reset.storage_id,
            count: pending_count,
        });
    }

    let cleanliness = query!(
        r#"
        SELECT
            (
                SELECT COUNT(*)
                FROM items_cache
                WHERE storage_id = ?1 AND sync_status != ?2
            ) AS dirty_items,
            (
                SELECT COUNT(*)
                FROM item_history
                WHERE storage_id = ?1 AND (source != ?3 OR sync_status != ?4)
            ) AS non_server_history
        "#,
        reset.storage_id,
        SyncStatus::Synced.as_i32(),
        HistorySource::Server.as_i32(),
        HistorySyncStatus::Confirmed.as_i32()
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let dirty_items = u64::try_from(
        cleanliness
            .try_get::<i64, _>("dirty_items")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "dirty item count is outside the supported range",
    })?;
    let non_server_history = u64::try_from(
        cleanliness
            .try_get::<i64, _>("non_server_history")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "local history count is outside the supported range",
    })?;
    if dirty_items != 0 || non_server_history != 0 {
        return Err(LocalSyncError::ProjectionNotClean {
            storage_id: reset.storage_id,
            dirty_items,
            non_server_history,
        });
    }

    let pending_deleted = delete_storage_rows(tx, "pending_changes", reset.storage_id).await?;
    let cursors_deleted = delete_storage_rows(tx, "sync_cursors", reset.storage_id).await?;
    let history_deleted = delete_storage_rows(tx, "item_history", reset.storage_id).await?;
    let items_deleted = delete_storage_rows(tx, "items_cache", reset.storage_id).await?;
    let vaults_deleted = delete_storage_rows(tx, "local_vaults", reset.storage_id).await?;

    let storage_metadata_updated = if let Some(storage) = &reset.replacement_storage {
        let expected = &reset.expected_storage;
        let result = query!(
            r#"
            UPDATE storages
            SET kind = ?1,
                name = ?2,
                server_url = ?3,
                server_name = ?4,
                server_fingerprint = ?5,
                account_subject = ?6,
                personal_vaults_enabled = ?7,
                auth_method = ?8
            WHERE id = ?9
              AND kind = ?10
              AND name = ?11
              AND server_url IS ?12
              AND server_name IS ?13
              AND server_fingerprint IS ?14
              AND account_subject IS ?15
              AND personal_vaults_enabled = ?16
              AND auth_method IS ?17
            "#,
            storage.kind.as_i32(),
            storage.name.as_str(),
            storage.server_url.as_deref(),
            storage.server_name.as_deref(),
            storage.server_fingerprint.as_deref(),
            storage.account_subject.as_deref(),
            storage.personal_vaults_enabled,
            storage.auth_method.map(|value| value.as_i32()),
            expected.id,
            expected.kind.as_i32(),
            expected.name.as_str(),
            expected.server_url.as_deref(),
            expected.server_name.as_deref(),
            expected.server_fingerprint.as_deref(),
            expected.account_subject.as_deref(),
            expected.personal_vaults_enabled,
            expected.auth_method.map(|value| value.as_i32())
        )
        .execute(&mut **tx)
        .await
        .map_err(LocalSyncError::Database)?;
        if result.rows_affected() != 1 {
            return Err(LocalSyncError::StorageBindingChanged {
                storage_id: reset.storage_id,
            });
        }
        true
    } else {
        false
    };

    Ok(ResetReceipt {
        pending_deleted,
        cursors_deleted,
        history_deleted,
        items_deleted,
        vaults_deleted,
        storage_metadata_updated,
    })
}

pub(super) async fn ensure_vault_references_are_storage_scoped(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    // `items_cache` and `item_history` currently reference a vault by its
    // globally unique id, not by `(storage_id, vault_id)`. Fail closed before
    // deleting target vaults if malformed rows from another storage would be
    // reached by SQLite's `ON DELETE CASCADE`.
    let references = sqlx_core::query::query::<Sqlite>(
        r#"
        SELECT
            (
                SELECT COUNT(*)
                FROM items_cache AS item
                WHERE item.storage_id != ?1
                  AND EXISTS (
                      SELECT 1
                      FROM local_vaults AS vault
                      WHERE vault.storage_id = ?1 AND vault.id = item.vault_id
                  )
            ) AS foreign_items,
            (
                SELECT COUNT(*)
                FROM item_history AS history
                WHERE history.storage_id != ?1
                  AND EXISTS (
                      SELECT 1
                      FROM local_vaults AS vault
                      WHERE vault.storage_id = ?1 AND vault.id = history.vault_id
                  )
            ) AS foreign_history
        "#,
    )
    .bind(storage_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let foreign_items = u64::try_from(
        references
            .try_get::<i64, _>("foreign_items")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "cross-storage item count is outside the supported range",
    })?;
    let foreign_history = u64::try_from(
        references
            .try_get::<i64, _>("foreign_history")
            .map_err(LocalSyncError::Database)?,
    )
    .map_err(|_| LocalSyncError::InvalidPlan {
        reason: "cross-storage history count is outside the supported range",
    })?;
    if foreign_items != 0 || foreign_history != 0 {
        return Err(LocalSyncError::CrossStorageVaultReference {
            storage_id,
            foreign_items,
            foreign_history,
        });
    }
    Ok(())
}

pub(super) async fn delete_storage_rows(
    tx: &mut Transaction<'static, Sqlite>,
    table: &'static str,
    storage_id: Uuid,
) -> Result<u64, LocalSyncError> {
    // `table` is internal and selected only by the fixed call sites above.
    let sql = format!("DELETE FROM {table} WHERE storage_id = ?1");
    sqlx_core::query::query::<Sqlite>(&sql)
        .bind(storage_id)
        .execute(&mut **tx)
        .await
        .map(|result| result.rows_affected())
        .map_err(LocalSyncError::Database)
}
