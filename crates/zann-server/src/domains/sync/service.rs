use sqlx_core::query_as::query_as;
use sqlx_postgres::Postgres;
use zann_core::vault_crypto as core_crypto;
use zann_core::{ChangeOp, ChangeType, Identity, VaultEncryptionType, VaultKind};
use zann_db::repo::{ChangeRepo, ItemHistoryRepo, ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::items::service::ITEM_HISTORY_LIMIT;
use crate::domains::sync::http::v1::handlers::push_apply::{apply_change, ApplyChangeResult};
use crate::domains::sync::http::v1::helpers::{
    can_push, decode_cursor, encode_cursor, parse_plaintext_payload,
};
use crate::domains::sync::http::v1::types::{
    SyncAppliedChange, SyncHistoryEntry, SyncPullChange, SyncPullRow, SyncPushChange,
    SyncPushConflict, SyncSharedHistoryEntry, SyncSharedPullChange, SyncSharedPushChange,
};
use crate::infra::db::apply_tx_isolation;
use crate::infra::metrics;

pub(crate) struct SyncPrep {
    pub(crate) vault: zann_core::Vault,
    pub(crate) device_id: uuid::Uuid,
}

pub(crate) enum SyncPrepError {
    Forbidden,
    NotFound,
    DbError,
    DeviceRequired,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SyncError {
    Forbidden,
    NotFound,
    Db,
    DeviceRequired,
    BadRequest(&'static str),
    Internal(&'static str),
}

pub(crate) struct SyncPullResult {
    pub(crate) changes: Vec<SyncPullChange>,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
}

pub(crate) struct SyncSharedPullResult {
    pub(crate) changes: Vec<SyncSharedPullChange>,
    pub(crate) next_cursor: String,
    pub(crate) has_more: bool,
    pub(crate) push_available: bool,
}

pub(crate) struct SyncPushResult {
    pub(crate) applied: Vec<String>,
    pub(crate) applied_changes: Vec<SyncAppliedChange>,
    pub(crate) conflicts: Vec<SyncPushConflict>,
    pub(crate) new_cursor: String,
}

pub(crate) async fn prepare_sync(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    action: &str,
    resource: &str,
) -> Result<SyncPrep, SyncPrepError> {
    let device_id = identity.device_id.ok_or(SyncPrepError::DeviceRequired)?;

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match vault_repo.get_by_id(vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(SyncPrepError::NotFound),
        Err(_) => {
            tracing::error!(event = "sync_prep_failed", "DB error");
            return Err(SyncPrepError::DbError);
        }
    };

    match state
        .policy_store
        .get()
        .evaluate(identity, action, resource)
    {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            tracing::warn!(
                event = "forbidden",
                action = action,
                resource = resource,
                "Access denied"
            );
            return Err(SyncPrepError::Forbidden);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, action, VaultScope::Sync).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = action,
                        resource = resource,
                        "Access denied"
                    );
                    return Err(SyncPrepError::Forbidden);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SyncPrepError::DbError);
                }
            }
        }
    }

    Ok(SyncPrep { vault, device_id })
}

pub(crate) async fn sync_pull(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    cursor: Option<String>,
    limit: i64,
) -> Result<SyncPullResult, SyncError> {
    let resource = "sync/pull";
    let prep = match prepare_sync(state, identity, vault_id, "read", resource).await {
        Ok(prep) => prep,
        Err(SyncPrepError::DeviceRequired) => return Err(SyncError::DeviceRequired),
        Err(SyncPrepError::NotFound) => return Err(SyncError::NotFound),
        Err(SyncPrepError::DbError) => return Err(SyncError::Db),
        Err(SyncPrepError::Forbidden) => return Err(SyncError::Forbidden),
    };
    let vault = prep.vault;

    let since_seq = match decode_cursor(cursor) {
        Ok(seq) => seq,
        Err(error) => return Err(SyncError::BadRequest(error.error)),
    };

    let limit = limit.clamp(1, 500);
    let query_limit = limit + 1;
    let mut rows = match query_as::<Postgres, SyncPullRow>(
        r#"
        SELECT
            c.seq as "seq",
            c.op as "op",
            i.id as "item_id",
            i.path as "path",
            i.name as "name",
            i.type_id as "type_id",
            i.payload_enc as "payload_enc",
            i.checksum as "checksum",
            i.updated_at as "updated_at"
        FROM changes c
        JOIN items i ON i.id = c.item_id
        WHERE c.vault_id = $1 AND c.seq > $2
        ORDER BY c.seq
        LIMIT $3
        "#,
    )
    .bind(vault.id)
    .bind(since_seq)
    .bind(query_limit)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(event = "sync_pull_failed", error = %err, "DB error");
            return Err(SyncError::Db);
        }
    };

    let has_more = rows.len() as i64 > limit;
    if has_more {
        rows.truncate(limit as usize);
    }

    let mut changes = Vec::with_capacity(rows.len());
    let mut last_seq = since_seq;
    let history_repo = ItemHistoryRepo::new(&state.db);
    for row in rows {
        let seq = row.seq;
        let op =
            ChangeOp::try_from(row.op).map_err(|_| SyncError::BadRequest("invalid_operation"))?;
        let payload_enc = if op == ChangeOp::Delete {
            None
        } else {
            Some(row.payload_enc)
        };
        let history = match history_repo
            .list_by_item_limit(row.item_id, ITEM_HISTORY_LIMIT)
            .await
        {
            Ok(entries) => {
                let mapped = entries
                    .into_iter()
                    .map(|entry| SyncHistoryEntry {
                        version: entry.version,
                        checksum: entry.checksum,
                        change_type: entry.change_type,
                        changed_by_name: entry.changed_by_name,
                        changed_by_email: entry.changed_by_email,
                        created_at: entry.created_at,
                        payload_enc: entry.payload_enc,
                    })
                    .collect::<Vec<_>>();
                tracing::info!(
                    event = "sync_pull_history",
                    item_id = %row.item_id,
                    count = mapped.len()
                );
                mapped
            }
            Err(err) => {
                tracing::warn!(
                    event = "sync_pull_history_failed",
                    item_id = %row.item_id,
                    error = %err
                );
                Vec::new()
            }
        };
        last_seq = seq;
        let operation = match op {
            ChangeOp::Create => ChangeType::Create,
            ChangeOp::Update => ChangeType::Update,
            ChangeOp::Delete => ChangeType::Delete,
        };
        changes.push(SyncPullChange {
            item_id: row.item_id.to_string(),
            operation,
            seq,
            updated_at: row.updated_at,
            checksum: row.checksum,
            payload_enc,
            path: row.path,
            name: row.name,
            type_id: row.type_id,
            history,
        });
    }

    let next_cursor = encode_cursor(last_seq);
    let push_available = can_push(state, identity, vault.id).await;

    Ok(SyncPullResult {
        changes,
        next_cursor,
        has_more,
        push_available,
    })
}

pub(crate) async fn sync_shared_pull(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    cursor: Option<String>,
    limit: i64,
) -> Result<SyncSharedPullResult, SyncError> {
    let resource = "sync/shared/pull";
    let policies = state.policy_store.get();

    let _device_id = identity.device_id.ok_or(SyncError::DeviceRequired)?;

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match vault_repo.get_by_id(vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(SyncError::NotFound),
        Err(_) => {
            tracing::error!(event = "sync_shared_pull_failed", "DB error");
            return Err(SyncError::Db);
        }
    };

    if vault.kind != VaultKind::Shared || vault.encryption_type != VaultEncryptionType::Server {
        return Err(SyncError::BadRequest("vault_not_shared"));
    }

    let Some(smk) = state.server_master_key.as_ref() else {
        return Err(SyncError::Internal("smk_missing"));
    };

    match policies.evaluate(identity, "read", resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            tracing::warn!(
                event = "forbidden",
                action = "read",
                resource = resource,
                "Access denied"
            );
            return Err(SyncError::Forbidden);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, "read", VaultScope::Sync).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = "read",
                        resource = resource,
                        "Access denied"
                    );
                    return Err(SyncError::Forbidden);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SyncError::Db);
                }
            }
        }
    }

    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!(
                event = "sync_shared_pull_failed",
                error = %err,
                "Vault key decrypt failed"
            );
            return Err(SyncError::Internal("payload_decrypt_failed"));
        }
    };

    let since_seq = match decode_cursor(cursor) {
        Ok(seq) => seq,
        Err(error) => return Err(SyncError::BadRequest(error.error)),
    };
    let limit = limit.clamp(1, 250);
    let rows: Vec<SyncPullRow> = match query_as::<Postgres, SyncPullRow>(
        r#"
        SELECT
            c.seq as "seq",
            c.op as "op",
            i.id as "item_id",
            i.path as "path",
            i.name as "name",
            i.type_id as "type_id",
            i.payload_enc as "payload_enc",
            i.checksum as "checksum",
            i.updated_at as "updated_at"
        FROM changes c
        JOIN items i ON i.id = c.item_id
        WHERE c.vault_id = $1
            AND c.seq > $2
        ORDER BY c.seq ASC
        LIMIT $3
        "#,
    )
    .bind(vault.id)
    .bind(since_seq)
    .bind(limit + 1)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(err) => {
            tracing::error!(event = "sync_shared_pull_failed", error = %err, "DB error");
            return Err(SyncError::Db);
        }
    };

    let has_more = rows.len() as i64 > limit;
    let mut rows = rows;
    if has_more {
        rows.truncate(limit as usize);
    }

    if since_seq == 0 && rows.is_empty() {
        let item_repo = ItemRepo::new(&state.db);
        let items = match item_repo.list_by_vault(vault.id, true).await {
            Ok(items) => items,
            Err(err) => {
                tracing::error!(event = "sync_shared_pull_failed", error = %err, "DB error");
                return Err(SyncError::Db);
            }
        };

        let change_repo = ChangeRepo::new(&state.db);
        let last_seq = change_repo.last_seq_for_vault(vault.id).await.unwrap_or(0);

        let history_repo = ItemHistoryRepo::new(&state.db);
        let mut changes = Vec::with_capacity(items.len());
        for item in items {
            let payload = if item.deleted_at.is_some() {
                None
            } else {
                match core_crypto::decrypt_payload_bytes(
                    &vault_key,
                    vault.id,
                    item.id,
                    &item.payload_enc,
                ) {
                    Ok(bytes) => match serde_json::from_slice(&bytes) {
                        Ok(payload) => Some(payload),
                        Err(_) => {
                            tracing::error!(
                                event = "sync_shared_pull_failed",
                                "Payload decode failed"
                            );
                            return Err(SyncError::Internal("payload_decrypt_failed"));
                        }
                    },
                    Err(err) => {
                        tracing::error!(
                            event = "sync_shared_pull_failed",
                            error = %err,
                            "Payload decrypt failed"
                        );
                        return Err(SyncError::Internal("payload_decrypt_failed"));
                    }
                }
            };
            let history = match history_repo
                .list_by_item_limit(item.id, ITEM_HISTORY_LIMIT)
                .await
            {
                Ok(entries) => {
                    let mut mapped = Vec::with_capacity(entries.len());
                    for entry in entries {
                        let payload = match core_crypto::decrypt_payload_bytes(
                            &vault_key,
                            vault.id,
                            item.id,
                            &entry.payload_enc,
                        ) {
                            Ok(bytes) => match serde_json::from_slice(&bytes) {
                                Ok(payload) => payload,
                                Err(_) => {
                                    tracing::error!(
                                        event = "sync_shared_pull_failed",
                                        "History payload decode failed"
                                    );
                                    return Err(SyncError::Internal("payload_decrypt_failed"));
                                }
                            },
                            Err(err) => {
                                tracing::error!(
                                    event = "sync_shared_pull_failed",
                                    error = %err,
                                    "History payload decrypt failed"
                                );
                                return Err(SyncError::Internal("payload_decrypt_failed"));
                            }
                        };
                        mapped.push(SyncSharedHistoryEntry {
                            version: entry.version,
                            checksum: entry.checksum,
                            change_type: entry.change_type,
                            changed_by_name: entry.changed_by_name,
                            changed_by_email: entry.changed_by_email,
                            created_at: entry.created_at.to_rfc3339(),
                            payload,
                        });
                    }
                    tracing::info!(
                        event = "sync_shared_pull_history",
                        item_id = %item.id,
                        count = mapped.len()
                    );
                    mapped
                }
                Err(err) => {
                    tracing::warn!(
                        event = "sync_shared_pull_history_failed",
                        item_id = %item.id,
                        error = %err
                    );
                    Vec::new()
                }
            };
            changes.push(SyncSharedPullChange {
                item_id: item.id.to_string(),
                operation: if item.deleted_at.is_some() {
                    ChangeType::Delete
                } else {
                    ChangeType::Update
                },
                seq: last_seq,
                updated_at: item.updated_at.to_rfc3339(),
                checksum: item.checksum,
                payload,
                path: item.path,
                name: item.name,
                type_id: item.type_id,
                history,
            });
        }

        return Ok(SyncSharedPullResult {
            changes,
            next_cursor: encode_cursor(last_seq),
            has_more: false,
            push_available: can_push(state, identity, vault.id).await,
        });
    }

    let mut changes = Vec::with_capacity(rows.len());
    let mut last_seq = since_seq;
    let history_repo = ItemHistoryRepo::new(&state.db);
    for row in rows {
        let seq = row.seq;
        let op =
            ChangeOp::try_from(row.op).map_err(|_| SyncError::BadRequest("invalid_operation"))?;
        let payload = if op == ChangeOp::Delete {
            None
        } else {
            match core_crypto::decrypt_payload_bytes(
                &vault_key,
                vault.id,
                row.item_id,
                &row.payload_enc,
            ) {
                Ok(bytes) => match serde_json::from_slice(&bytes) {
                    Ok(payload) => Some(payload),
                    Err(_) => {
                        tracing::error!(event = "sync_shared_pull_failed", "Payload decode failed");
                        return Err(SyncError::Internal("payload_decrypt_failed"));
                    }
                },
                Err(err) => {
                    tracing::error!(
                        event = "sync_shared_pull_failed",
                        error = %err,
                        "Payload decrypt failed"
                    );
                    return Err(SyncError::Internal("payload_decrypt_failed"));
                }
            }
        };
        let history = match history_repo
            .list_by_item_limit(row.item_id, ITEM_HISTORY_LIMIT)
            .await
        {
            Ok(entries) => {
                let mut mapped = Vec::with_capacity(entries.len());
                for entry in entries {
                    let payload = match core_crypto::decrypt_payload_bytes(
                        &vault_key,
                        vault.id,
                        row.item_id,
                        &entry.payload_enc,
                    ) {
                        Ok(bytes) => match serde_json::from_slice(&bytes) {
                            Ok(payload) => payload,
                            Err(_) => {
                                tracing::error!(
                                    event = "sync_shared_pull_failed",
                                    "History payload decode failed"
                                );
                                return Err(SyncError::Internal("payload_decrypt_failed"));
                            }
                        },
                        Err(err) => {
                            tracing::error!(
                                event = "sync_shared_pull_failed",
                                error = %err,
                                "History payload decrypt failed"
                            );
                            return Err(SyncError::Internal("payload_decrypt_failed"));
                        }
                    };
                    mapped.push(SyncSharedHistoryEntry {
                        version: entry.version,
                        checksum: entry.checksum,
                        change_type: entry.change_type,
                        changed_by_name: entry.changed_by_name,
                        changed_by_email: entry.changed_by_email,
                        created_at: entry.created_at.to_rfc3339(),
                        payload,
                    });
                }
                tracing::info!(
                    event = "sync_shared_pull_history",
                    item_id = %row.item_id,
                    count = mapped.len()
                );
                mapped
            }
            Err(err) => {
                tracing::warn!(
                    event = "sync_shared_pull_history_failed",
                    item_id = %row.item_id,
                    error = %err
                );
                Vec::new()
            }
        };
        last_seq = seq;
        let operation = match op {
            ChangeOp::Create => ChangeType::Create,
            ChangeOp::Update => ChangeType::Update,
            ChangeOp::Delete => ChangeType::Delete,
        };
        changes.push(SyncSharedPullChange {
            item_id: row.item_id.to_string(),
            operation,
            seq,
            updated_at: row.updated_at.to_rfc3339(),
            checksum: row.checksum,
            payload,
            path: row.path,
            name: row.name,
            type_id: row.type_id,
            history,
        });
    }

    let next_cursor = encode_cursor(last_seq);
    let push_available = can_push(state, identity, vault.id).await;

    Ok(SyncSharedPullResult {
        changes,
        next_cursor,
        has_more,
        push_available,
    })
}

pub(crate) async fn sync_push(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    changes: Vec<SyncPushChange>,
) -> Result<SyncPushResult, SyncError> {
    let resource = "sync/push";
    let prep = match prepare_sync(state, identity, vault_id, "write", resource).await {
        Ok(prep) => prep,
        Err(SyncPrepError::DeviceRequired) => return Err(SyncError::DeviceRequired),
        Err(SyncPrepError::NotFound) => return Err(SyncError::NotFound),
        Err(SyncPrepError::DbError) => return Err(SyncError::Db),
        Err(SyncPrepError::Forbidden) => return Err(SyncError::Forbidden),
    };
    let vault = prep.vault;
    let device_id = prep.device_id;

    let mut applied = Vec::new();
    let mut applied_changes = Vec::new();
    let mut conflicts = Vec::new();

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(event = "sync_push_failed", error = %err, "DB begin failed");
            return Err(SyncError::Db);
        }
    };
    if let Err(err) = apply_tx_isolation(&mut tx, state.db_tx_isolation).await {
        tracing::error!(event = "sync_push_failed", error = %err, "DB begin failed");
        return Err(SyncError::Db);
    }

    for change in changes {
        match apply_change(&mut tx, identity, device_id, vault.id, change).await {
            Ok(ApplyChangeResult::Applied {
                item_id,
                applied_change,
            }) => {
                applied.push(item_id.to_string());
                applied_changes.push(applied_change);
            }
            Ok(ApplyChangeResult::Conflict(conflict)) => {
                conflicts.push(conflict);
            }
            Err(err) => {
                if let Err(rollback_err) = tx.rollback().await {
                    tracing::error!(
                        event = "sync_push_failed",
                        error = %rollback_err,
                        "DB rollback failed"
                    );
                }
                return match err.status {
                    axum::http::StatusCode::BAD_REQUEST => Err(SyncError::BadRequest(err.error)),
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR => {
                        Err(SyncError::Internal(err.error))
                    }
                    _ => Err(SyncError::Internal(err.error)),
                };
            }
        }
    }

    if !conflicts.is_empty() {
        if let Err(err) = tx.rollback().await {
            tracing::error!(event = "sync_push_failed", error = %err, "DB rollback failed");
        }
        let change_repo = ChangeRepo::new(&state.db);
        let new_seq = change_repo.last_seq_for_vault(vault.id).await.unwrap_or(0);
        let new_cursor = encode_cursor(new_seq);
        return Ok(SyncPushResult {
            applied: Vec::new(),
            applied_changes: Vec::new(),
            conflicts,
            new_cursor,
        });
    }

    if let Err(err) = tx.commit().await {
        tracing::error!(event = "sync_push_failed", error = %err, "DB commit failed");
        return Err(SyncError::Db);
    }

    let change_repo = ChangeRepo::new(&state.db);
    let new_seq = change_repo.last_seq_for_vault(vault.id).await.unwrap_or(0);
    let new_cursor = encode_cursor(new_seq);

    Ok(SyncPushResult {
        applied,
        applied_changes,
        conflicts,
        new_cursor,
    })
}

pub(crate) async fn sync_shared_push(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    changes: Vec<SyncSharedPushChange>,
) -> Result<SyncPushResult, SyncError> {
    let resource = "sync/shared/push";
    let policies = state.policy_store.get();

    let _device_id = identity.device_id.ok_or(SyncError::DeviceRequired)?;

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match vault_repo.get_by_id(vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return Err(SyncError::NotFound),
        Err(_) => {
            tracing::error!(event = "sync_shared_push_failed", "DB error");
            return Err(SyncError::Db);
        }
    };

    if vault.kind != VaultKind::Shared || vault.encryption_type != VaultEncryptionType::Server {
        return Err(SyncError::BadRequest("vault_not_shared"));
    }

    let Some(smk) = state.server_master_key.as_ref() else {
        return Err(SyncError::Internal("smk_missing"));
    };

    match policies.evaluate(identity, "write", resource) {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny => {
            metrics::forbidden_access(resource);
            tracing::warn!(
                event = "forbidden",
                action = "write",
                resource = resource,
                "Access denied"
            );
            return Err(SyncError::Forbidden);
        }
        PolicyDecision::NoMatch => {
            match vault_role_allows(state, identity, vault.id, "write", VaultScope::Sync).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::forbidden_access(resource);
                    tracing::warn!(
                        event = "forbidden",
                        action = "write",
                        resource = resource,
                        "Access denied"
                    );
                    return Err(SyncError::Forbidden);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SyncError::Db);
                }
            }
        }
    }

    let mut payload_changes = Vec::with_capacity(changes.len());
    for change in changes {
        if change.operation == ChangeType::Delete {
            payload_changes.push(SyncPushChange {
                item_id: change.item_id,
                operation: change.operation,
                payload_enc: None,
                checksum: None,
                path: change.path,
                name: change.name,
                type_id: change.type_id,
                base_seq: change.base_seq,
            });
            continue;
        }

        let Some(payload) = change.payload else {
            return Err(SyncError::BadRequest("missing_payload"));
        };
        let Some(type_id) = change.type_id.as_deref() else {
            return Err(SyncError::BadRequest("missing_type_id"));
        };
        let type_id = type_id.trim();
        if type_id.is_empty() {
            return Err(SyncError::BadRequest("missing_type_id"));
        }
        let payload_bytes = match parse_plaintext_payload(&payload) {
            Ok(payload) => payload,
            Err(error) => return Err(SyncError::BadRequest(error.error)),
        };
        let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
            Ok(key) => key,
            Err(err) => {
                tracing::error!(
                    event = "sync_shared_push_failed",
                    error = %err,
                    "Key decrypt failed"
                );
                return Err(SyncError::Internal("payload_encrypt_failed"));
            }
        };
        let payload_enc = match core_crypto::encrypt_payload_bytes(
            &vault_key,
            vault.id,
            change.item_id,
            &payload_bytes,
        ) {
            Ok(enc) => enc,
            Err(err) => {
                tracing::error!(
                    event = "sync_shared_push_failed",
                    error = %err,
                    "Encryption failed"
                );
                return Err(SyncError::Internal("payload_encrypt_failed"));
            }
        };
        let checksum = core_crypto::payload_checksum(&payload_enc);

        payload_changes.push(SyncPushChange {
            item_id: change.item_id,
            operation: change.operation,
            payload_enc: Some(payload_enc),
            checksum: Some(checksum),
            path: change.path,
            name: change.name,
            type_id: Some(type_id.to_string()),
            base_seq: change.base_seq,
        });
    }

    sync_push(state, identity, vault_id, payload_changes).await
}
