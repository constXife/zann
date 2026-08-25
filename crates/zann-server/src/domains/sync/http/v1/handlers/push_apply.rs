use axum::http::StatusCode;
use chrono::Utc;
use sqlx_core::row::Row;
use sqlx_postgres::PgConnection;
use uuid::Uuid;

use super::super::helpers::{actor_snapshot, find_path_conflict, prune_item_history};
use super::super::types::{SyncAppliedChange, SyncPushChange, SyncPushConflict};
use super::super::ITEM_HISTORY_LIMIT;
use crate::domains::items::contract::{
    canonical_create_location, canonical_type_id, canonical_update_location, next_item_version,
    validate_existing_type_id, validate_personal_ciphertext, ItemContractError,
    MAX_CIPHERTEXT_BYTES,
};
use zann_core::Identity;
use zann_core::{ChangeOp, ChangeType, Item, SyncStatus};

pub(crate) struct ApplyChangeError {
    pub(crate) status: StatusCode,
    pub(crate) error: &'static str,
}

pub(crate) enum ApplyChangeResult {
    Applied {
        item_id: Uuid,
        applied_change: SyncAppliedChange,
    },
    Conflict(SyncPushConflict),
}

fn db_error() -> ApplyChangeError {
    ApplyChangeError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        error: "db_error",
    }
}

fn verify_payload_pair(
    payload_enc: Option<Vec<u8>>,
    checksum: Option<String>,
    required: bool,
) -> Result<Option<(Vec<u8>, String)>, ApplyChangeError> {
    match (payload_enc, checksum) {
        (Some(payload_enc), Some(checksum)) => {
            validate_personal_ciphertext(&payload_enc, &checksum).map_err(contract_error)?;
            Ok(Some((payload_enc, checksum)))
        }
        (Some(_), None) => Err(ApplyChangeError {
            status: StatusCode::BAD_REQUEST,
            error: "missing_checksum",
        }),
        (None, Some(_)) => Err(ApplyChangeError {
            status: StatusCode::BAD_REQUEST,
            error: "checksum_without_payload",
        }),
        (None, None) if required => Err(ApplyChangeError {
            status: StatusCode::BAD_REQUEST,
            error: "missing_payload",
        }),
        (None, None) => Ok(None),
    }
}

fn contract_error(error: ItemContractError) -> ApplyChangeError {
    ApplyChangeError {
        status: if error == ItemContractError::PayloadTooLarge {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        },
        error: error.code(),
    }
}

fn conflict_for_item(item: &Item, reason: &'static str, server_seq: i64) -> ApplyChangeResult {
    ApplyChangeResult::Conflict(SyncPushConflict {
        item_id: item.id.to_string(),
        reason,
        server_seq,
        server_updated_at: item.updated_at.to_rfc3339(),
    })
}

fn current_generation_applied(item: &Item, seq: i64) -> ApplyChangeResult {
    ApplyChangeResult::Applied {
        item_id: item.id,
        applied_change: SyncAppliedChange {
            item_id: item.id.to_string(),
            seq,
            updated_at: item.updated_at.to_rfc3339(),
            deleted_at: item.deleted_at.as_ref().map(|value| value.to_rfc3339()),
        },
    }
}

async fn load_bounded_item(
    conn: &mut PgConnection,
    item_id: Uuid,
    vault_id: Uuid,
) -> Result<Option<Item>, ApplyChangeError> {
    let metadata = query!(
        r#"
        SELECT (
            is_canonical_item_path(path)
            AND octet_length(path)::BIGINT <= 500
            AND octet_length(name)::BIGINT BETWEEN 1 AND 200
            AND name = canonical_item_basename(path)
            AND is_canonical_item_type(type_id)
            AND octet_length(type_id)::BIGINT <= 128
            AND octet_length(checksum)::BIGINT = 64
            AND checksum ~ '^[0-9a-f]{64}$'
            AND octet_length(payload_enc)::BIGINT BETWEEN 1 AND $3
            AND (tags IS NULL OR octet_length(tags::text)::BIGINT <= 65536)
        ) AS within_bounds
        FROM items
        WHERE id = $1 AND vault_id = $2
        "#,
        item_id,
        vault_id,
        MAX_CIPHERTEXT_BYTES as i64
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|err| {
        tracing::error!(event = "sync_push_item_metadata_failed", error = %err, "DB error");
        db_error()
    })?;
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    if !metadata
        .try_get::<bool, _>("within_bounds")
        .map_err(|_| db_error())?
    {
        return Err(ApplyChangeError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: "invalid_item_row",
        });
    }

    query_as!(
        Item,
        r#"
        SELECT
            id as "id", vault_id as "vault_id", path, name, type_id,
            tags as "tags", favorite as "favorite", payload_enc, checksum,
            version as "version", row_version as "row_version", device_id as "device_id",
            sync_status as "sync_status", deleted_at as "deleted_at",
            deleted_by_user_id as "deleted_by_user_id",
            deleted_by_device_id as "deleted_by_device_id",
            created_at as "created_at", updated_at as "updated_at"
        FROM items
        WHERE id = $1 AND vault_id = $2
        "#,
        item_id,
        vault_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|err| {
        tracing::error!(event = "sync_push_item_load_failed", error = %err, "DB error");
        db_error()
    })
}

async fn insert_item_history(
    conn: &mut PgConnection,
    history: &zann_core::ItemHistory,
) -> Result<(), ApplyChangeError> {
    let result = query!(
        r"
        INSERT INTO item_history AS existing (
            id, item_id, payload_enc, checksum, version, change_type, fields_changed,
            changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
            changed_by_device_name, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (item_id, version) DO UPDATE
        SET item_id = existing.item_id
        WHERE existing.payload_enc IS NOT DISTINCT FROM excluded.payload_enc
          AND existing.checksum IS NOT DISTINCT FROM excluded.checksum
        ",
        history.id,
        history.item_id,
        &history.payload_enc,
        history.checksum.as_str(),
        history.version,
        history.change_type.as_i32(),
        history.fields_changed.as_ref(),
        history.changed_by_user_id,
        history.changed_by_email.as_str(),
        history.changed_by_name.as_deref(),
        history.changed_by_device_id,
        history.changed_by_device_name.as_deref(),
        history.created_at
    )
    .execute(&mut *conn)
    .await
    .map_err(|err| {
        tracing::error!(
            event = "sync_push_history_insert_failed",
            error = %err,
            item_id = %history.item_id,
            "Failed to insert item history"
        );
        db_error()
    })?;
    if result.rows_affected() == 0 {
        tracing::error!(
            event = "sync_push_history_generation_conflict",
            item_id = %history.item_id,
            version = history.version,
            "Conflicting item history generation"
        );
        return Err(db_error());
    }
    Ok(())
}

async fn enforce_item_history_limit(
    conn: &mut PgConnection,
    item_id: Uuid,
) -> Result<(), ApplyChangeError> {
    prune_item_history(&mut *conn, item_id, ITEM_HISTORY_LIMIT)
        .await
        .map(|_| ())
        .map_err(|err| {
            tracing::error!(
                event = "sync_push_history_prune_failed",
                error = %err,
                item_id = %item_id,
                "Failed to prune item history"
            );
            db_error()
        })
}

pub(crate) async fn apply_change(
    conn: &mut PgConnection,
    identity: &Identity,
    device_id: Uuid,
    vault_id: Uuid,
    change: SyncPushChange,
) -> Result<ApplyChangeResult, ApplyChangeError> {
    let operation = change.operation;
    let base_seq = change.base_seq.unwrap_or(0);
    // Serialize writers of an existing item before checking the exact current
    // generation. Without this lock, two updates with the same base cursor can
    // both pass the check and the loser fails later as an ambiguous DB error.
    query!(
        r#"
        SELECT id
        FROM items
        WHERE id = $1 AND vault_id = $2
        FOR UPDATE
        "#,
        change.item_id,
        vault_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|err| {
        tracing::error!(event = "sync_push_failed", error = %err, "DB error");
        db_error()
    })?;

    let current_seq_row = query!(
        r#"
        SELECT c.seq
        FROM items i
        JOIN changes c
          ON c.item_id = i.id
         AND c.vault_id = i.vault_id
         AND c.version = i.version
        WHERE i.vault_id = $1 AND i.id = $2
        "#,
        vault_id,
        change.item_id
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|err| {
        tracing::error!(event = "sync_push_failed", error = %err, "DB error");
        db_error()
    })?;
    let current_seq = current_seq_row
        .map(|row| row.try_get::<i64, _>("seq"))
        .transpose()
        .map_err(|err| {
            tracing::error!(event = "sync_push_failed", error = %err, "DB error");
            db_error()
        })?;

    if let Some(server_seq) = current_seq {
        if server_seq != base_seq {
            let updated_at = match query!(
                r"
                SELECT updated_at
                FROM items
                WHERE id = $1 AND vault_id = $2
                ",
                change.item_id,
                vault_id
            )
            .fetch_optional(&mut *conn)
            .await
            {
                Ok(Some(row)) => row
                    .try_get::<chrono::DateTime<Utc>, _>("updated_at")
                    .ok()
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| Utc::now().to_rfc3339()),
                Ok(None) => Utc::now().to_rfc3339(),
                Err(err) => {
                    tracing::error!(
                        event = "sync_push_conflict_timestamp_failed",
                        error = %err,
                        item_id = %change.item_id,
                        "Failed to load conflict timestamp"
                    );
                    Utc::now().to_rfc3339()
                }
            };
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "concurrent_modification",
                server_seq,
                server_updated_at: updated_at,
            }));
        }
    }

    let existing = load_bounded_item(conn, change.item_id, vault_id).await?;

    // The row lock and exact generation check above make this a state-machine
    // decision, rather than relying on the deferred database trigger to reject
    // an invalid transition at commit time. In particular, Update never
    // revives a tombstone, Restore is the only tombstone -> Active transition,
    // and an exact retry of Delete is a read-only success.
    if let Some(item) = existing.as_ref() {
        let state = (item.sync_status, item.deleted_at.is_some());
        match operation {
            ChangeType::Create => {}
            ChangeType::Update | ChangeType::Restore | ChangeType::Delete => {
                let Some(server_seq) = current_seq else {
                    return Ok(conflict_for_item(item, "generation_conflict", 0));
                };
                match (operation, state) {
                    (ChangeType::Update, (SyncStatus::Active, false))
                    | (ChangeType::Restore, (SyncStatus::Tombstone, true))
                    | (ChangeType::Delete, (SyncStatus::Active, false)) => {}
                    (ChangeType::Update, (SyncStatus::Tombstone, true)) => {
                        return Ok(conflict_for_item(item, "item_deleted", server_seq));
                    }
                    (ChangeType::Restore, (SyncStatus::Active, false)) => {
                        return Ok(conflict_for_item(item, "item_not_deleted", server_seq));
                    }
                    (ChangeType::Delete, (SyncStatus::Tombstone, true)) => {
                        return Ok(current_generation_applied(item, server_seq));
                    }
                    _ => {
                        return Ok(conflict_for_item(item, "invalid_item_state", server_seq));
                    }
                }
            }
        }
    }

    let now = Utc::now();
    let item_version = match (operation, existing) {
        (ChangeType::Create, None) => {
            let (payload_enc, checksum) =
                verify_payload_pair(change.payload_enc, change.checksum, true)?
                    .expect("required payload pair");
            let path = match change.path.as_deref() {
                Some(value) => value,
                _ => {
                    return Err(ApplyChangeError {
                        status: StatusCode::BAD_REQUEST,
                        error: "missing_path",
                    });
                }
            };
            let (path, name) =
                canonical_create_location(path, change.name.as_deref()).map_err(contract_error)?;
            let type_id = match change.type_id.as_deref() {
                Some(value) => canonical_type_id(value).map_err(contract_error)?,
                _ => {
                    return Err(ApplyChangeError {
                        status: StatusCode::BAD_REQUEST,
                        error: "missing_type_id",
                    });
                }
            };

            let conflict_updated_at = find_path_conflict(conn, vault_id, &path, None)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "sync_push_path_conflict_failed",
                        error = %err,
                        item_id = %change.item_id,
                        "Failed to check path conflicts"
                    );
                    db_error()
                })?;
            if let Some(updated_at) = conflict_updated_at {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: change.item_id.to_string(),
                    reason: "already_exists",
                    server_seq: current_seq.unwrap_or(0),
                    server_updated_at: updated_at,
                }));
            }

            let item = Item {
                id: change.item_id,
                vault_id,
                path,
                name,
                type_id,
                tags: None,
                favorite: false,
                payload_enc,
                checksum,
                version: 1,
                row_version: 1,
                device_id,
                sync_status: SyncStatus::Active,
                deleted_at: None,
                deleted_by_user_id: None,
                deleted_by_device_id: None,
                created_at: now,
                updated_at: now,
            };
            let item_version = item.version;

            let insert_result = query!(
                r"
                INSERT INTO items (
                    id, vault_id, path, name, type_id, tags, favorite, payload_enc, checksum,
                    version, row_version, device_id, sync_status, deleted_at, deleted_by_user_id,
                    deleted_by_device_id, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
                ON CONFLICT DO NOTHING
                ",
                item.id,
                item.vault_id,
                item.path,
                item.name,
                item.type_id,
                item.tags.as_ref(),
                item.favorite,
                &item.payload_enc,
                item.checksum,
                item.version,
                item.row_version,
                item.device_id,
                item.sync_status.as_i32(),
                item.deleted_at,
                item.deleted_by_user_id,
                item.deleted_by_device_id,
                item.created_at,
                item.updated_at
            )
            .execute(&mut *conn)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "sync_push_item_insert_failed",
                    error = %err,
                    item_id = %item.id,
                    "Failed to insert item"
                );
                db_error()
            })?;
            if insert_result.rows_affected() == 0 {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: change.item_id.to_string(),
                    reason: "already_exists",
                    server_seq: 0,
                    server_updated_at: now.to_rfc3339(),
                }));
            }
            item_version
        }
        (ChangeType::Create, Some(_)) => {
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "already_exists",
                server_seq: current_seq.unwrap_or(0),
                server_updated_at: now.to_rfc3339(),
            }));
        }
        (ChangeType::Update, Some(mut item)) => {
            let payload_update = verify_payload_pair(change.payload_enc, change.checksum, false)?;
            let payload_changed = payload_update.as_ref().is_some_and(|(payload, checksum)| {
                payload != &item.payload_enc || checksum != &item.checksum
            });
            let (next_path, next_name) = canonical_update_location(
                &item.path,
                change.path.as_deref(),
                change.name.as_deref(),
            )
            .map_err(contract_error)?;
            let conflict_updated_at = find_path_conflict(conn, vault_id, &next_path, Some(item.id))
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "sync_push_path_conflict_failed",
                        error = %err,
                        item_id = %item.id,
                        "Failed to check path conflicts"
                    );
                    db_error()
                })?;
            if let Some(updated_at) = conflict_updated_at {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: item.id.to_string(),
                    reason: "already_exists",
                    server_seq: current_seq.unwrap_or(0),
                    server_updated_at: updated_at,
                }));
            }

            let actor = actor_snapshot(conn, identity, Some(device_id)).await;
            if payload_changed {
                let history = zann_core::ItemHistory {
                    id: Uuid::now_v7(),
                    item_id: item.id,
                    payload_enc: item.payload_enc.clone(),
                    checksum: item.checksum.clone(),
                    version: item.version,
                    change_type: ChangeType::Update,
                    fields_changed: None,
                    changed_by_user_id: identity.user_id,
                    changed_by_email: actor.email,
                    changed_by_name: actor.name,
                    changed_by_device_id: Some(device_id),
                    changed_by_device_name: actor.device_name,
                    created_at: now,
                };
                insert_item_history(conn, &history).await?;
                enforce_item_history_limit(conn, item.id).await?;
            }

            item.path = next_path;
            item.name = next_name;
            validate_existing_type_id(&item.type_id, change.type_id.as_deref())
                .map_err(contract_error)?;

            if let Some((payload_enc, checksum)) = payload_update {
                item.payload_enc = payload_enc;
                item.checksum = checksum;
            }

            item.version = next_item_version(item.version).map_err(contract_error)?;
            item.row_version = item
                .row_version
                .checked_add(1)
                .ok_or_else(|| contract_error(ItemContractError::InvalidVersion))?;
            item.device_id = device_id;
            item.updated_at = now;
            let item_version = item.version;

            let Ok(update_result) = query!(
                r"
                UPDATE items
                SET path = $2,
                    name = $3,
                    type_id = $4,
                    payload_enc = $5,
                    checksum = $6,
                    version = $7,
                    row_version = $8,
                    device_id = $9,
                    updated_at = $10
                WHERE id = $1
                  AND vault_id = $11
                  AND sync_status = $12
                  AND deleted_at IS NULL
                ",
                item.id,
                item.path,
                item.name,
                item.type_id,
                &item.payload_enc,
                item.checksum,
                item.version,
                item.row_version,
                item.device_id,
                item.updated_at,
                vault_id,
                SyncStatus::Active.as_i32()
            )
            .execute(&mut *conn)
            .await
            else {
                return Err(ApplyChangeError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    error: "db_error",
                });
            };
            if update_result.rows_affected() == 0 {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: item.id.to_string(),
                    reason: "concurrent_modification",
                    server_seq: current_seq.unwrap_or(0),
                    server_updated_at: item.updated_at.to_rfc3339(),
                }));
            }
            item_version
        }
        (ChangeType::Restore, Some(mut item)) => {
            let payload_update = verify_payload_pair(change.payload_enc, change.checksum, false)?;
            let actor = actor_snapshot(conn, identity, Some(device_id)).await;
            let history = zann_core::ItemHistory {
                id: Uuid::now_v7(),
                item_id: item.id,
                payload_enc: item.payload_enc.clone(),
                checksum: item.checksum.clone(),
                version: item.version,
                change_type: ChangeType::Restore,
                fields_changed: None,
                changed_by_user_id: identity.user_id,
                changed_by_email: actor.email,
                changed_by_name: actor.name,
                changed_by_device_id: Some(device_id),
                changed_by_device_name: actor.device_name,
                created_at: now,
            };
            insert_item_history(conn, &history).await?;
            enforce_item_history_limit(conn, item.id).await?;
            query!(
                r#"
                UPDATE attachments
                SET deleted_at = NULL
                WHERE item_id = $1
                "#,
                item.id
            )
            .execute(&mut *conn)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "sync_push_attachment_restore_failed",
                    error = %err,
                    item_id = %item.id,
                    "Failed to restore attachment state"
                );
                db_error()
            })?;

            let (next_path, next_name) = canonical_update_location(
                &item.path,
                change.path.as_deref(),
                change.name.as_deref(),
            )
            .map_err(contract_error)?;
            item.path = next_path;
            item.name = next_name;
            validate_existing_type_id(&item.type_id, change.type_id.as_deref())
                .map_err(contract_error)?;

            if let Some((payload_enc, checksum)) = payload_update {
                item.payload_enc = payload_enc;
                item.checksum = checksum;
            }

            item.version = next_item_version(item.version).map_err(contract_error)?;
            item.row_version = item
                .row_version
                .checked_add(1)
                .ok_or_else(|| contract_error(ItemContractError::InvalidVersion))?;
            item.device_id = device_id;
            item.sync_status = SyncStatus::Active;
            item.deleted_at = None;
            item.deleted_by_user_id = None;
            item.deleted_by_device_id = None;
            item.updated_at = now;
            let item_version = item.version;

            let Ok(update_result) = query!(
                r"
                UPDATE items
                SET path = $2,
                    name = $3,
                    type_id = $4,
                    payload_enc = $5,
                    checksum = $6,
                    version = $7,
                    row_version = $8,
                    device_id = $9,
                    sync_status = $10,
                    deleted_at = $11,
                    deleted_by_user_id = $12,
                    deleted_by_device_id = $13,
                    updated_at = $14
                WHERE id = $1
                  AND vault_id = $15
                  AND sync_status = $16
                  AND deleted_at IS NOT NULL
                ",
                item.id,
                item.path,
                item.name,
                item.type_id,
                &item.payload_enc,
                item.checksum,
                item.version,
                item.row_version,
                item.device_id,
                item.sync_status.as_i32(),
                item.deleted_at,
                item.deleted_by_user_id,
                item.deleted_by_device_id,
                item.updated_at,
                vault_id,
                SyncStatus::Tombstone.as_i32()
            )
            .execute(&mut *conn)
            .await
            else {
                return Err(ApplyChangeError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    error: "db_error",
                });
            };
            if update_result.rows_affected() == 0 {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: item.id.to_string(),
                    reason: "concurrent_modification",
                    server_seq: current_seq.unwrap_or(0),
                    server_updated_at: item.updated_at.to_rfc3339(),
                }));
            }
            item_version
        }
        (ChangeType::Delete, Some(mut item)) => {
            let actor = actor_snapshot(conn, identity, Some(device_id)).await;
            let history = zann_core::ItemHistory {
                id: Uuid::now_v7(),
                item_id: item.id,
                payload_enc: item.payload_enc.clone(),
                checksum: item.checksum.clone(),
                version: item.version,
                change_type: ChangeType::Delete,
                fields_changed: None,
                changed_by_user_id: identity.user_id,
                changed_by_email: actor.email,
                changed_by_name: actor.name,
                changed_by_device_id: Some(device_id),
                changed_by_device_name: actor.device_name,
                created_at: now,
            };
            insert_item_history(conn, &history).await?;
            enforce_item_history_limit(conn, item.id).await?;
            query!(
                r#"
                UPDATE attachments
                SET deleted_at = $2
                WHERE item_id = $1 AND deleted_at IS NULL
                "#,
                item.id,
                now
            )
            .execute(&mut *conn)
            .await
            .map_err(|err| {
                tracing::error!(
                    event = "sync_push_attachment_delete_failed",
                    error = %err,
                    item_id = %item.id,
                    "Failed to tombstone attachment state"
                );
                db_error()
            })?;

            item.version = next_item_version(item.version).map_err(contract_error)?;
            item.row_version = item
                .row_version
                .checked_add(1)
                .ok_or_else(|| contract_error(ItemContractError::InvalidVersion))?;
            item.device_id = device_id;
            item.sync_status = SyncStatus::Tombstone;
            item.deleted_at = Some(now);
            item.deleted_by_user_id = Some(identity.user_id);
            item.deleted_by_device_id = Some(device_id);
            item.updated_at = now;
            let item_version = item.version;

            let Ok(update_result) = query!(
                r"
                UPDATE items
                SET version = $2,
                    row_version = $3,
                    device_id = $4,
                    sync_status = $5,
                    deleted_at = $6,
                    deleted_by_user_id = $7,
                    deleted_by_device_id = $8,
                    updated_at = $9
                WHERE id = $1
                  AND vault_id = $10
                  AND sync_status = $11
                  AND deleted_at IS NULL
                ",
                item.id,
                item.version,
                item.row_version,
                item.device_id,
                item.sync_status.as_i32(),
                item.deleted_at,
                item.deleted_by_user_id,
                item.deleted_by_device_id,
                item.updated_at,
                vault_id,
                SyncStatus::Active.as_i32()
            )
            .execute(&mut *conn)
            .await
            else {
                return Err(ApplyChangeError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    error: "db_error",
                });
            };
            if update_result.rows_affected() == 0 {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: item.id.to_string(),
                    reason: "concurrent_modification",
                    server_seq: current_seq.unwrap_or(0),
                    server_updated_at: item.updated_at.to_rfc3339(),
                }));
            }
            item_version
        }
        (_, None) => {
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "missing_item",
                server_seq: current_seq.unwrap_or(0),
                server_updated_at: now.to_rfc3339(),
            }));
        }
    };

    let op = match operation {
        ChangeType::Delete => ChangeOp::Delete,
        ChangeType::Update | ChangeType::Restore => ChangeOp::Update,
        ChangeType::Create => ChangeOp::Create,
    };
    let inserted = match query!(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (item_id, version) DO NOTHING
        RETURNING seq
        "#,
        vault_id,
        change.item_id,
        op.as_i32(),
        item_version,
        device_id,
        now
    )
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "generation_conflict",
                server_seq: current_seq.unwrap_or(0),
                server_updated_at: now.to_rfc3339(),
            }));
        }
        Err(err) => {
            if err.as_database_error().and_then(|error| error.constraint())
                == Some("changes_generation_semantics")
            {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: change.item_id.to_string(),
                    reason: "generation_conflict",
                    server_seq: current_seq.unwrap_or(0),
                    server_updated_at: now.to_rfc3339(),
                }));
            }
            tracing::error!(
                event = "sync_push_change_insert_failed",
                error = %err,
                item_id = %change.item_id,
                "Failed to insert change"
            );
            return Err(db_error());
        }
    };
    let seq = inserted.try_get::<i64, _>("seq").map_err(|err| {
        tracing::error!(
            event = "sync_push_change_insert_failed",
            error = %err,
            item_id = %change.item_id,
            "Failed to read change sequence"
        );
        db_error()
    })?;
    let deleted_at = if operation == ChangeType::Delete {
        Some(now.to_rfc3339())
    } else {
        None
    };

    Ok(ApplyChangeResult::Applied {
        item_id: change.item_id,
        applied_change: SyncAppliedChange {
            item_id: change.item_id.to_string(),
            seq,
            updated_at: now.to_rfc3339(),
            deleted_at,
        },
    })
}
