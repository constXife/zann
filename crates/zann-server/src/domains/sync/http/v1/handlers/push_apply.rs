use axum::http::StatusCode;
use chrono::Utc;
use sqlx_core::row::Row;
use sqlx_postgres::PgConnection;
use uuid::Uuid;

use super::super::helpers::{
    actor_snapshot, find_path_conflict, normalize_path_and_name, prune_item_history,
};
use super::super::types::{SyncAppliedChange, SyncPushChange, SyncPushConflict};
use super::super::ITEM_HISTORY_LIMIT;
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

pub(crate) async fn apply_change(
    conn: &mut PgConnection,
    identity: &Identity,
    device_id: Uuid,
    vault_id: Uuid,
    change: SyncPushChange,
) -> Result<ApplyChangeResult, ApplyChangeError> {
    let operation = change.operation.as_str();
    let base_seq = change.base_seq.unwrap_or(0);
    let max_seq: Option<i64> = query!(
        r#"
        SELECT MAX(seq) as "seq"
        FROM changes
        WHERE vault_id = $1 AND item_id = $2
        "#,
        vault_id,
        change.item_id
    )
    .fetch_optional(&mut *conn)
    .await
    .ok()
    .and_then(|row| row.and_then(|r| r.try_get("seq").ok()));

    if let Some(server_seq) = max_seq {
        if base_seq > 0 && server_seq > base_seq {
            let updated_at = query!(
                r"
                SELECT updated_at
                FROM items
                WHERE id = $1
                ",
                change.item_id
            )
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .and_then(|row| row.and_then(|r| r.try_get("updated_at").ok()))
            .unwrap_or_else(|| Utc::now().to_rfc3339());
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "concurrent_modification",
                server_seq,
                server_updated_at: updated_at,
            }));
        }
    }

    let existing = query_as!(
        Item,
        r#"
        SELECT
            id as "id",
            vault_id as "vault_id",
            path,
            name,
            type_id,
            tags as "tags",
            favorite as "favorite",
            payload_enc,
            checksum,
            version as "version",
            row_version as "row_version",
            device_id as "device_id",
            sync_status as "sync_status",
            deleted_at as "deleted_at",
            deleted_by_user_id as "deleted_by_user_id",
            deleted_by_device_id as "deleted_by_device_id",
            created_at as "created_at",
            updated_at as "updated_at"
        FROM items
        WHERE id = $1
        "#,
        change.item_id
    )
    .fetch_optional(&mut *conn)
    .await;

    let now = Utc::now();
    let item_version = match (operation, existing) {
        ("create", Ok(None)) => {
            let payload_enc = match change.payload_enc {
                Some(payload) => payload,
                None => {
                    return Err(ApplyChangeError {
                        status: StatusCode::BAD_REQUEST,
                        error: "missing_payload",
                    });
                }
            };
            let checksum = match change.checksum.as_deref() {
                Some(value) if !value.trim().is_empty() => value.trim().to_string(),
                _ => {
                    return Err(ApplyChangeError {
                        status: StatusCode::BAD_REQUEST,
                        error: "missing_checksum",
                    });
                }
            };
            let path = match change.path.as_deref() {
                Some(value) if !value.trim().is_empty() => value.trim().to_string(),
                _ => {
                    return Err(ApplyChangeError {
                        status: StatusCode::BAD_REQUEST,
                        error: "missing_path",
                    });
                }
            };
            let (path, name) = normalize_path_and_name(&path, Some(&path), change.name.as_deref());
            let type_id = match change.type_id.as_deref() {
                Some(value) if !value.trim().is_empty() => value.trim().to_string(),
                _ => {
                    return Err(ApplyChangeError {
                        status: StatusCode::BAD_REQUEST,
                        error: "missing_type_id",
                    });
                }
            };

            if let Some(updated_at) = find_path_conflict(conn, vault_id, &path, None).await {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: change.item_id.to_string(),
                    reason: "already_exists",
                    server_seq: max_seq.unwrap_or(0),
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

            if query!(
                r"
                INSERT INTO items (
                    id, vault_id, path, name, type_id, tags, favorite, payload_enc, checksum,
                    version, row_version, device_id, sync_status, deleted_at, deleted_by_user_id,
                    deleted_by_device_id, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
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
                item.sync_status.as_str(),
                item.deleted_at,
                item.deleted_by_user_id,
                item.deleted_by_device_id,
                item.created_at,
                item.updated_at
            )
            .execute(&mut *conn)
            .await
            .is_err()
            {
                return Err(ApplyChangeError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    error: "db_error",
                });
            }
            item_version
        }
        ("create", Ok(Some(_))) => {
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "already_exists",
                server_seq: max_seq.unwrap_or(0),
                server_updated_at: now.to_rfc3339(),
            }));
        }
        ("update", Ok(Some(mut item))) => {
            let payload_changed = match (change.payload_enc.as_ref(), change.checksum.as_deref()) {
                (Some(_), Some(checksum)) => {
                    let trimmed = checksum.trim();
                    trimmed.is_empty() || trimmed != item.checksum
                }
                (Some(_), None) => true,
                (None, _) => false,
            };
            let (next_path, next_name) =
                normalize_path_and_name(&item.path, change.path.as_deref(), change.name.as_deref());
            if let Some(updated_at) =
                find_path_conflict(conn, vault_id, &next_path, Some(item.id)).await
            {
                return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                    item_id: item.id.to_string(),
                    reason: "already_exists",
                    server_seq: max_seq.unwrap_or(0),
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
                let _ = query!(
                    r"
                    INSERT INTO item_history (
                        id, item_id, payload_enc, checksum, version, change_type, fields_changed,
                        changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
                        changed_by_device_name, created_at
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    ON CONFLICT (item_id, version) DO NOTHING
                    ",
                    history.id,
                    history.item_id,
                    &history.payload_enc,
                    history.checksum.as_str(),
                    history.version,
                    history.change_type.as_str(),
                    history.fields_changed.as_ref(),
                    history.changed_by_user_id,
                    history.changed_by_email.as_str(),
                    history.changed_by_name.as_deref(),
                    history.changed_by_device_id,
                    history.changed_by_device_name.as_deref(),
                    history.created_at
                )
                .execute(&mut *conn)
                .await;
                let _ = prune_item_history(&mut *conn, item.id, ITEM_HISTORY_LIMIT).await;
            }

            item.path = next_path;
            item.name = next_name;
            if let Some(type_id) = change.type_id.as_deref() {
                if !type_id.trim().is_empty() {
                    item.type_id = type_id.trim().to_string();
                }
            }

            if let Some(payload) = change.payload_enc {
                item.payload_enc = payload;
            }
            if let Some(checksum) = change.checksum.as_deref() {
                if !checksum.trim().is_empty() {
                    item.checksum = checksum.trim().to_string();
                }
            }

            item.version = item.version.saturating_add(1);
            item.row_version = item.row_version.saturating_add(1);
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
                item.updated_at
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
                    server_seq: max_seq.unwrap_or(0),
                    server_updated_at: item.updated_at.to_rfc3339(),
                }));
            }
            item_version
        }
        ("restore", Ok(Some(mut item))) => {
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
            let _ = query!(
                r"
                INSERT INTO item_history (
                    id, item_id, payload_enc, checksum, version, change_type, fields_changed,
                    changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
                    changed_by_device_name, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (item_id, version) DO NOTHING
                ",
                history.id,
                history.item_id,
                &history.payload_enc,
                history.checksum.as_str(),
                history.version,
                history.change_type.as_str(),
                history.fields_changed.as_ref(),
                history.changed_by_user_id,
                history.changed_by_email.as_str(),
                history.changed_by_name.as_deref(),
                history.changed_by_device_id,
                history.changed_by_device_name.as_deref(),
                history.created_at
            )
            .execute(&mut *conn)
            .await;
            let _ = prune_item_history(&mut *conn, item.id, ITEM_HISTORY_LIMIT).await;

            if let Some(path) = change.path.as_deref() {
                if !path.trim().is_empty() {
                    item.path = path.trim().to_string();
                }
            }
            if let Some(name) = change.name.as_deref() {
                if !name.trim().is_empty() {
                    item.name = name.trim().to_string();
                }
            }
            if let Some(type_id) = change.type_id.as_deref() {
                let type_id = type_id.trim();
                if !type_id.is_empty() {
                    item.type_id = type_id.to_string();
                }
            }

            if let Some(payload) = change.payload_enc {
                item.payload_enc = payload;
            }
            if let Some(checksum) = change.checksum.as_deref() {
                if !checksum.trim().is_empty() {
                    item.checksum = checksum.trim().to_string();
                }
            }

            item.version = item.version.saturating_add(1);
            item.row_version = item.row_version.saturating_add(1);
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
                item.sync_status.as_str(),
                item.deleted_at,
                item.deleted_by_user_id,
                item.deleted_by_device_id,
                item.updated_at
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
                    server_seq: max_seq.unwrap_or(0),
                    server_updated_at: item.updated_at.to_rfc3339(),
                }));
            }
            item_version
        }
        ("delete", Ok(Some(mut item))) => {
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
            let _ = query!(
                r"
                INSERT INTO item_history (
                    id, item_id, payload_enc, checksum, version, change_type, fields_changed,
                    changed_by_user_id, changed_by_email, changed_by_name, changed_by_device_id,
                    changed_by_device_name, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (item_id, version) DO NOTHING
                ",
                history.id,
                history.item_id,
                &history.payload_enc,
                history.checksum.as_str(),
                history.version,
                history.change_type.as_str(),
                history.fields_changed.as_ref(),
                history.changed_by_user_id,
                history.changed_by_email.as_str(),
                history.changed_by_name.as_deref(),
                history.changed_by_device_id,
                history.changed_by_device_name.as_deref(),
                history.created_at
            )
            .execute(&mut *conn)
            .await;
            let _ = prune_item_history(&mut *conn, item.id, ITEM_HISTORY_LIMIT).await;

            item.version = item.version.saturating_add(1);
            item.row_version = item.row_version.saturating_add(1);
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
                ",
                item.id,
                item.version,
                item.row_version,
                item.device_id,
                item.sync_status.as_str(),
                item.deleted_at,
                item.deleted_by_user_id,
                item.deleted_by_device_id,
                item.updated_at
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
                    server_seq: max_seq.unwrap_or(0),
                    server_updated_at: item.updated_at.to_rfc3339(),
                }));
            }
            item_version
        }
        (_, Ok(None)) => {
            return Ok(ApplyChangeResult::Conflict(SyncPushConflict {
                item_id: change.item_id.to_string(),
                reason: "missing_item",
                server_seq: max_seq.unwrap_or(0),
                server_updated_at: now.to_rfc3339(),
            }));
        }
        _ => {
            return Err(ApplyChangeError {
                status: StatusCode::BAD_REQUEST,
                error: "invalid_operation",
            });
        }
    };

    let op = match operation {
        "delete" => ChangeOp::Delete,
        "update" => ChangeOp::Update,
        _ => ChangeOp::Create,
    };
    let inserted = query!(
        r#"
        INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING seq
        "#,
        vault_id,
        change.item_id,
        op.as_str(),
        item_version,
        device_id,
        now
    )
    .fetch_one(&mut *conn)
    .await;
    let seq = inserted
        .ok()
        .and_then(|row| row.try_get::<i64, _>("seq").ok())
        .unwrap_or(item_version);
    let deleted_at = if operation == "delete" {
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
