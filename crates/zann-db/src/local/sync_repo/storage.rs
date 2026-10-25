use super::*;

pub(super) async fn ensure_materialized_scope(
    tx: &mut Transaction<'static, Sqlite>,
    scope: LocalSyncScope,
) -> Result<(), LocalSyncError> {
    ensure_storage_kinds_bounded(tx, scope.storage_id).await?;
    let storage = query!(
        r#"
        SELECT 1
        FROM storages
        WHERE id = ?1
          AND CASE
            WHEN typeof(kind) = 'integer' THEN kind = ?2
            ELSE 0
          END
        "#,
        scope.storage_id,
        StorageKind::Remote.as_i32()
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let vault = bounded_vault_scope_membership(tx, scope.storage_id, scope.vault_id)
        .await
        .map_err(LocalSyncError::Database)?;
    if storage.is_none() || vault != Some(true) {
        return Err(LocalSyncError::InvalidPlan {
            reason: "sync scope is not materialized locally",
        });
    }
    Ok(())
}

pub(crate) async fn ensure_storage_proof(
    tx: &mut Transaction<'static, Sqlite>,
    proof: &LocalStorageProof,
) -> Result<(), LocalSyncError> {
    ensure_storage_kinds_bounded(tx, proof.id).await?;
    ensure_storage_projection_bounded(tx, proof.id).await?;
    let row = query!(
        r#"
        SELECT 1
        FROM storages
        WHERE id = ?1
          AND kind = ?2
          AND name = ?3
          AND server_url IS ?4
          AND server_name IS ?5
          AND server_fingerprint IS ?6
          AND account_subject IS ?7
          AND personal_vaults_enabled = ?8
          AND auth_method IS ?9
        "#,
        proof.id,
        proof.kind.as_i32(),
        proof.name.as_str(),
        proof.server_url.as_deref(),
        proof.server_name.as_deref(),
        proof.server_fingerprint.as_deref(),
        proof.account_subject.as_deref(),
        proof.personal_vaults_enabled,
        proof.auth_method.map(|value| value.as_i32())
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if row.is_none() {
        return Err(LocalSyncError::StorageBindingChanged {
            storage_id: proof.id,
        });
    }
    Ok(())
}

pub(super) async fn ensure_storage_projection_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    let valid = query!(
        r#"
        SELECT CASE WHEN
            CASE WHEN typeof(id) IN ('blob', 'text')
                THEN octet_length(id) IN (16, 36) ELSE 0 END
            AND CASE WHEN typeof(kind) = 'integer'
                THEN kind IN (1, 2) ELSE 0 END
            AND CASE WHEN typeof(name) = 'text'
                THEN octet_length(name) BETWEEN 1 AND ?2 ELSE 0 END
            AND (server_url IS NULL OR CASE WHEN typeof(server_url) = 'text'
                THEN octet_length(server_url) BETWEEN 1 AND ?3 ELSE 0 END)
            AND (server_name IS NULL OR CASE WHEN typeof(server_name) = 'text'
                THEN octet_length(server_name) BETWEEN 1 AND ?4 ELSE 0 END)
            AND (server_fingerprint IS NULL OR CASE
                WHEN typeof(server_fingerprint) = 'text'
                THEN octet_length(server_fingerprint) BETWEEN 1 AND ?4 ELSE 0 END)
            AND (account_subject IS NULL OR CASE WHEN typeof(account_subject) = 'text'
                THEN octet_length(account_subject) BETWEEN 1 AND ?4 ELSE 0 END)
            AND CASE WHEN typeof(personal_vaults_enabled) = 'integer'
                THEN personal_vaults_enabled IN (0, 1) ELSE 0 END
            AND CASE
                WHEN auth_method IS NULL THEN 1
                WHEN typeof(auth_method) = 'integer'
                    THEN auth_method IN (1, 2, 3)
                ELSE 0
            END
            AND CASE
                WHEN sync_config_repository_fp IS NULL THEN
                    sync_stable_target_fp IS NULL
                    AND sync_config_revision IS NULL
                    AND sync_config_content_fp IS NULL
                WHEN kind != ?5 THEN 0
                WHEN typeof(sync_config_repository_fp) != 'blob' THEN 0
                WHEN octet_length(sync_config_repository_fp) != 32 THEN 0
                WHEN typeof(sync_stable_target_fp) != 'blob' THEN 0
                WHEN octet_length(sync_stable_target_fp) != 32 THEN 0
                WHEN typeof(sync_config_revision) != 'blob' THEN 0
                WHEN octet_length(sync_config_revision) != 8 THEN 0
                WHEN typeof(sync_config_content_fp) != 'blob' THEN 0
                WHEN octet_length(sync_config_content_fp) != 32 THEN 0
                ELSE 1
            END
        THEN 1 ELSE 0 END AS valid
        FROM storages
        WHERE id = ?1
        "#,
        storage_id,
        MAX_DISPLAY_NAME_BYTES as i64,
        MAX_SERVER_URL_BYTES as i64,
        MAX_SERVER_METADATA_BYTES as i64,
        StorageKind::Remote.as_i32()
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
        return Err(LocalSyncError::StorageBindingChanged { storage_id });
    }
    Ok(())
}

pub(crate) async fn ensure_single_remote_storage(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    ensure_storage_kinds_bounded(tx, storage_id).await?;
    let row = query!(
        r#"
        SELECT COUNT(*) AS count
        FROM (
            SELECT 1
            FROM storages
            WHERE CASE
                WHEN typeof(kind) = 'integer' THEN kind = ?1
                ELSE 0
            END
            LIMIT 2
        )
        "#,
        StorageKind::Remote.as_i32()
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let count: i64 = row.try_get("count").map_err(LocalSyncError::Database)?;
    if count != 1 {
        return Err(LocalSyncError::StorageBindingChanged { storage_id });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalGenerationBindingState {
    Unbound,
    Exact,
    Older,
}

/// Reads only scalar comparison results after the storage preflight has
/// proved every generation field fixed-size.  No persisted digest is copied
/// into application memory.
pub(crate) async fn inspect_generation_binding(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    generation: &LocalSyncGenerationProof,
) -> Result<LocalGenerationBindingState, LocalSyncError> {
    ensure_storage_projection_bounded(tx, storage_id).await?;
    let revision = generation.revision_be();
    let row = query!(
        r#"
        SELECT CASE
            WHEN sync_config_repository_fp IS NULL THEN 0
            WHEN sync_config_repository_fp != ?2 OR sync_stable_target_fp != ?3 THEN 3
            WHEN sync_config_revision > ?4 THEN 3
            WHEN sync_config_revision = ?4 AND sync_config_content_fp != ?5 THEN 3
            WHEN sync_config_revision = ?4 THEN 1
            ELSE 2
        END AS generation_state
        FROM storages
        WHERE id = ?1
        "#,
        storage_id,
        generation.repository_fingerprint.as_slice(),
        generation.stable_target_fingerprint.as_slice(),
        revision.as_slice(),
        generation.config_content_fingerprint.as_slice()
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    let state = row
        .ok_or(LocalSyncError::StorageGenerationChanged { storage_id })?
        .try_get::<i64, _>("generation_state")
        .map_err(LocalSyncError::Database)?;
    match state {
        0 => Ok(LocalGenerationBindingState::Unbound),
        1 => Ok(LocalGenerationBindingState::Exact),
        2 => Ok(LocalGenerationBindingState::Older),
        _ => Err(LocalSyncError::StorageGenerationChanged { storage_id }),
    }
}

pub(crate) async fn claim_generation(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    generation: &LocalSyncGenerationProof,
) -> Result<(), LocalSyncError> {
    let revision = generation.revision_be();
    let updated = query!(
        r#"
        UPDATE storages
        SET sync_config_repository_fp = ?2,
            sync_stable_target_fp = ?3,
            sync_config_revision = ?4,
            sync_config_content_fp = ?5
        WHERE id = ?1
          AND kind = ?6
          AND sync_config_repository_fp IS NULL
          AND sync_stable_target_fp IS NULL
          AND sync_config_revision IS NULL
          AND sync_config_content_fp IS NULL
        "#,
        storage_id,
        generation.repository_fingerprint.as_slice(),
        generation.stable_target_fingerprint.as_slice(),
        revision.as_slice(),
        generation.config_content_fingerprint.as_slice(),
        StorageKind::Remote.as_i32()
    )
    .execute(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?
    .rows_affected();
    if updated != 1 {
        return Err(LocalSyncError::StorageGenerationChanged { storage_id });
    }
    Ok(())
}

pub(crate) async fn ensure_bound_generation_and_advance(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
    generation: &LocalSyncGenerationProof,
) -> Result<(), LocalSyncError> {
    match inspect_generation_binding(tx, storage_id, generation).await? {
        LocalGenerationBindingState::Unbound => {
            Err(LocalSyncError::StorageGenerationChanged { storage_id })
        }
        LocalGenerationBindingState::Exact => Ok(()),
        LocalGenerationBindingState::Older => {
            let revision = generation.revision_be();
            let updated = query!(
                r#"
                UPDATE storages
                SET sync_config_revision = ?4,
                    sync_config_content_fp = ?5
                WHERE id = ?1
                  AND sync_config_repository_fp = ?2
                  AND sync_stable_target_fp = ?3
                  AND sync_config_revision < ?4
                "#,
                storage_id,
                generation.repository_fingerprint.as_slice(),
                generation.stable_target_fingerprint.as_slice(),
                revision.as_slice(),
                generation.config_content_fingerprint.as_slice()
            )
            .execute(&mut **tx)
            .await
            .map_err(LocalSyncError::Database)?
            .rows_affected();
            if updated != 1 {
                return Err(LocalSyncError::StorageGenerationChanged { storage_id });
            }
            Ok(())
        }
    }
}

pub(super) async fn ensure_storage_kinds_bounded(
    tx: &mut Transaction<'static, Sqlite>,
    storage_id: Uuid,
) -> Result<(), LocalSyncError> {
    let corrupt = query!(
        r#"
        SELECT 1
        FROM storages
        WHERE CASE
            WHEN typeof(id) NOT IN ('blob', 'text') THEN 1
            WHEN octet_length(id) NOT IN (16, 36) THEN 1
            WHEN typeof(kind) != 'integer' THEN 1
            WHEN kind NOT IN (1, 2) THEN 1
            ELSE 0
        END
        LIMIT 1
        "#
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(LocalSyncError::Database)?;
    if corrupt.is_some() {
        return Err(LocalSyncError::StorageBindingChanged { storage_id });
    }
    Ok(())
}
