use serde::Serialize;
use sqlx_core::from_row::FromRow;
use sqlx_core::query_as::query_as;
use sqlx_core::query_scalar::query_scalar;
use sqlx_core::row::Row;
use sqlx_postgres::{PgRow, Postgres};
use std::io::Write;
use zann_core::{ChangeOp, ChangeType, Identity, Vault, VaultEncryptionType, VaultKind};
use zann_crypto::crypto::SecretKey;
use zann_crypto::vault_crypto as core_crypto;
use zann_crypto::EncryptedPayload;
use zann_db::repo::VaultRepo;
use zann_db::PgPool;

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;
use crate::domains::errors::ServiceError;
use crate::domains::items::contract::{
    canonical_type_id, validate_server_typed_payload, MAX_PUSH_CHANGES,
};
use crate::domains::secrets::service::{decode_secret_payload_bytes, SECRET_TYPE_ID};
use crate::domains::sync::http::v1::handlers::push_apply::{apply_change, ApplyChangeResult};
use crate::domains::sync::http::v1::helpers::{can_push, decode_cursor, encode_cursor};
use crate::domains::sync::http::v1::types::{
    SyncAppliedChange, SyncHistoryEntry, SyncPullChange, SyncPushChange, SyncPushConflict,
    SyncSharedHistoryEntry, SyncSharedPullChange, SyncSharedPushChange,
};
use crate::domains::sync::SYNC_CIPHERTEXT_MAX_BYTES;
use crate::infra::db::apply_tx_isolation;
use crate::infra::metrics;

const SYNC_PULL_PAGE_LIMIT: i64 = 4;
const SYNC_HISTORY_LIMIT: i64 = 5;
const SYNC_ITEM_PATH_MAX_BYTES: i64 = 500;
const SYNC_ITEM_NAME_MAX_BYTES: i64 = 200;
const SYNC_TYPE_ID_MAX_BYTES: i64 = 128;
const SYNC_CHECKSUM_MAX_BYTES: i64 = 64;
const SYNC_EMAIL_MAX_BYTES: i64 = 320;
const SYNC_DISPLAY_NAME_MAX_BYTES: i64 = 200;
const SYNC_PULL_RESPONSE_MAX_BYTES: usize = 30 * 1_024 * 1_024;
const SYNC_VAULT_KEY_MAX_BYTES: i64 = 64 * 1_024;
const SYNC_VAULT_TAGS_MAX_BYTES: i64 = 64 * 1_024;

struct SyncPageRow {
    seq: i64,
    op: i32,
    item_id: uuid::Uuid,
    path: Option<String>,
    name: Option<String>,
    type_id: Option<String>,
    payload_enc: Option<Vec<u8>>,
    checksum: Option<String>,
    updated_at: chrono::DateTime<chrono::Utc>,
    within_bounds: bool,
    has_more: bool,
}

impl FromRow<'_, PgRow> for SyncPageRow {
    fn from_row(row: &PgRow) -> Result<Self, sqlx_core::Error> {
        Ok(Self {
            seq: row.try_get("seq")?,
            op: i32::from(row.try_get::<i16, _>("op")?),
            item_id: row.try_get("item_id")?,
            path: row.try_get("path")?,
            name: row.try_get("name")?,
            type_id: row.try_get("type_id")?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            updated_at: row.try_get("updated_at")?,
            within_bounds: row.try_get("within_bounds")?,
            has_more: row.try_get("has_more")?,
        })
    }
}

struct SyncHistoryRecord {
    version: i64,
    checksum: String,
    change_type: ChangeType,
    changed_by_name: Option<String>,
    changed_by_email: String,
    created_at: chrono::DateTime<chrono::Utc>,
    payload_enc: Vec<u8>,
}

struct SyncHistoryDbRow {
    version: i64,
    checksum: Option<String>,
    change_type: i32,
    changed_by_name: Option<String>,
    changed_by_email: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    payload_enc: Option<Vec<u8>>,
    within_bounds: bool,
}

impl FromRow<'_, PgRow> for SyncHistoryDbRow {
    fn from_row(row: &PgRow) -> Result<Self, sqlx_core::Error> {
        Ok(Self {
            version: row.try_get("version")?,
            checksum: row.try_get("checksum")?,
            change_type: i32::from(row.try_get::<i16, _>("change_type")?),
            changed_by_name: row.try_get("changed_by_name")?,
            changed_by_email: row.try_get("changed_by_email")?,
            created_at: row.try_get("created_at")?,
            payload_enc: row.try_get("payload_enc")?,
            within_bounds: row.try_get("within_bounds")?,
        })
    }
}

struct ResponseBudgetWriter {
    bytes_written: usize,
    exceeded: bool,
}

impl Write for ResponseBudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes_written.saturating_add(bytes.len()) > SYNC_PULL_RESPONSE_MAX_BYTES {
            self.exceeded = true;
            return Err(std::io::Error::other("sync pull response budget exceeded"));
        }
        self.bytes_written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) struct SyncPrep {
    pub(crate) vault: zann_core::Vault,
    pub(crate) device_id: uuid::Uuid,
}

pub(crate) type SyncPrepError = ServiceError;
pub(crate) type SyncError = ServiceError;

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

fn page_state<T>(
    rows: &[T],
    since_seq: i64,
    sequence: impl Fn(&T) -> i64,
    has_more: impl Fn(&T) -> bool,
) -> (bool, i64) {
    let has_more = rows.first().is_some_and(has_more);
    let next_seq = rows.last().map_or(since_seq, sequence);
    (has_more, next_seq)
}

fn clamp_pull_limit(limit: i64) -> i64 {
    limit.clamp(1, SYNC_PULL_PAGE_LIMIT)
}

fn validate_push_change_count(count: usize) -> Result<(), SyncError> {
    if count > MAX_PUSH_CHANGES {
        return Err(SyncError::BadRequest("too_many_changes"));
    }
    Ok(())
}

async fn fetch_sync_page(
    pool: &PgPool,
    vault_id: uuid::Uuid,
    since_seq: i64,
    limit: i64,
) -> Result<Vec<SyncPageRow>, SyncError> {
    query_as::<Postgres, SyncPageRow>(
        r#"
        WITH candidates AS MATERIALIZED (
            SELECT
                c.seq,
                c.op,
                c.item_id,
                c.version,
                c.vault_id,
                (
                    is_canonical_item_path(i.path)
                    AND octet_length(i.path)::BIGINT <= $5
                    AND octet_length(i.name)::BIGINT BETWEEN 1 AND $6
                    AND i.name = canonical_item_basename(i.path)
                    AND is_canonical_item_type(i.type_id)
                    AND octet_length(i.type_id)::BIGINT <= $7
                    AND octet_length(i.checksum)::BIGINT = $8
                    AND i.checksum ~ '^[0-9a-f]{64}$'
                    AND (
                        c.op = 3
                        OR octet_length(i.payload_enc)::BIGINT <= $9
                    )
                ) AS within_bounds
            FROM changes AS c
            JOIN items AS i
              ON i.id = c.item_id
             AND i.version = c.version
             AND i.vault_id = c.vault_id
            WHERE c.vault_id = $1
              AND c.seq > $2
            ORDER BY c.seq ASC
            LIMIT $3
        ),
        page AS MATERIALIZED (
            SELECT *
            FROM candidates
            ORDER BY seq ASC
            LIMIT $4
        )
        SELECT
            page.seq AS "seq",
            page.op AS "op",
            page.item_id AS "item_id",
            CASE WHEN page.within_bounds THEN item.path END AS "path",
            CASE WHEN page.within_bounds THEN item.name END AS "name",
            CASE WHEN page.within_bounds THEN item.type_id END AS "type_id",
            CASE
                WHEN page.within_bounds AND page.op <> 3 THEN item.payload_enc
            END AS "payload_enc",
            CASE WHEN page.within_bounds THEN item.checksum END AS "checksum",
            item.updated_at AS "updated_at",
            page.within_bounds AS "within_bounds",
            EXISTS (
                SELECT 1
                FROM candidates
                ORDER BY seq ASC
                OFFSET $4
                LIMIT 1
            ) AS "has_more"
        FROM page
        JOIN items AS item
          ON item.id = page.item_id
         AND item.version = page.version
         AND item.vault_id = page.vault_id
        ORDER BY page.seq ASC
        "#,
    )
    .bind(vault_id)
    .bind(since_seq)
    .bind(limit + 1)
    .bind(limit)
    .bind(SYNC_ITEM_PATH_MAX_BYTES)
    .bind(SYNC_ITEM_NAME_MAX_BYTES)
    .bind(SYNC_TYPE_ID_MAX_BYTES)
    .bind(SYNC_CHECKSUM_MAX_BYTES)
    .bind(SYNC_CIPHERTEXT_MAX_BYTES as i64)
    .fetch_all(pool)
    .await
    .map_err(|err| {
        tracing::error!(event = "sync_pull_failed", error = %err, "DB error");
        SyncError::DbError
    })
}

async fn fetch_sync_history(
    pool: &PgPool,
    item_id: uuid::Uuid,
) -> Result<Vec<SyncHistoryRecord>, SyncError> {
    let rows = query_as::<Postgres, SyncHistoryDbRow>(
        r#"
        WITH candidates AS MATERIALIZED (
            SELECT
                id,
                version,
                change_type,
                created_at,
                (
                    octet_length(payload_enc)::BIGINT <= $3
                    AND octet_length(checksum)::BIGINT = $4
                    AND checksum ~ '^[0-9a-f]{64}$'
                    AND octet_length(changed_by_email)::BIGINT BETWEEN 1 AND $5
                    AND (
                        changed_by_name IS NULL
                        OR octet_length(changed_by_name)::BIGINT <= $6
                    )
                ) AS within_bounds
            FROM item_history
            WHERE item_id = $1
            ORDER BY version DESC
            LIMIT $2
        )
        SELECT
            candidate.version AS "version",
            candidate.change_type AS "change_type",
            candidate.created_at AS "created_at",
            candidate.within_bounds AS "within_bounds",
            CASE WHEN candidate.within_bounds THEN history.payload_enc END AS "payload_enc",
            CASE WHEN candidate.within_bounds THEN history.checksum END AS "checksum",
            CASE WHEN candidate.within_bounds THEN history.changed_by_name END AS "changed_by_name",
            CASE WHEN candidate.within_bounds THEN history.changed_by_email END AS "changed_by_email"
        FROM candidates AS candidate
        JOIN item_history AS history ON history.id = candidate.id
        ORDER BY candidate.version DESC
        "#,
    )
    .bind(item_id)
    .bind(SYNC_HISTORY_LIMIT)
    .bind(SYNC_CIPHERTEXT_MAX_BYTES as i64)
    .bind(SYNC_CHECKSUM_MAX_BYTES)
    .bind(SYNC_EMAIL_MAX_BYTES)
    .bind(SYNC_DISPLAY_NAME_MAX_BYTES)
    .fetch_all(pool)
    .await
    .map_err(|err| {
        tracing::error!(
            event = "sync_pull_history_failed",
            item_id = %item_id,
            error = %err
        );
        SyncError::DbError
    })?;

    rows.into_iter()
        .map(|row| {
            if !row.within_bounds {
                return Err(SyncError::PayloadTooLarge("sync_history_too_large"));
            }
            let change_type = ChangeType::try_from(row.change_type)
                .map_err(|_| SyncError::BadRequest("invalid_history_operation"))?;
            Ok(SyncHistoryRecord {
                version: row.version,
                checksum: row
                    .checksum
                    .ok_or(SyncError::Internal("invalid_history_row"))?,
                change_type,
                changed_by_name: row.changed_by_name,
                changed_by_email: row
                    .changed_by_email
                    .ok_or(SyncError::Internal("invalid_history_row"))?,
                created_at: row.created_at,
                payload_enc: row
                    .payload_enc
                    .ok_or(SyncError::Internal("invalid_history_row"))?,
            })
        })
        .collect()
}

fn ensure_response_budget<T: Serialize>(value: &T) -> Result<(), SyncError> {
    let mut writer = ResponseBudgetWriter {
        bytes_written: 0,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_) if writer.exceeded => Err(SyncError::PayloadTooLarge("sync_page_too_large")),
        Err(err) => {
            tracing::error!(event = "sync_pull_encode_failed", error = %err);
            Err(SyncError::Internal("response_encode_failed"))
        }
    }
}

fn take_bounded_item_fields(
    row: &mut SyncPageRow,
) -> Result<(String, String, String, String), SyncError> {
    if !row.within_bounds {
        return Err(SyncError::PayloadTooLarge("sync_item_too_large"));
    }
    Ok((
        row.path
            .take()
            .ok_or(SyncError::Internal("invalid_sync_row"))?,
        row.name
            .take()
            .ok_or(SyncError::Internal("invalid_sync_row"))?,
        row.type_id
            .take()
            .ok_or(SyncError::Internal("invalid_sync_row"))?,
        row.checksum
            .take()
            .ok_or(SyncError::Internal("invalid_sync_row"))?,
    ))
}

/// Checks only fixed-size metadata before asking the repository to materialize
/// the encrypted vault key and tags. The migration enforces the same bounds for
/// future rows; this remains fail-closed for dirty/imported databases.
async fn fetch_bounded_sync_vault(
    pool: &PgPool,
    vault_id: uuid::Uuid,
) -> Result<Option<Vault>, SyncError> {
    let within_bounds = query_scalar::<Postgres, bool>(
        r#"
        SELECT
            octet_length(vault_key_enc)::BIGINT BETWEEN 1 AND $2
            AND octet_length(tags::text)::BIGINT <= $3
        FROM vaults
        WHERE id = $1
        "#,
    )
    .bind(vault_id)
    .bind(SYNC_VAULT_KEY_MAX_BYTES)
    .bind(SYNC_VAULT_TAGS_MAX_BYTES)
    .fetch_optional(pool)
    .await
    .map_err(|err| {
        tracing::error!(event = "sync_vault_metadata_failed", error = %err, "DB error");
        SyncError::DbError
    })?;

    let Some(within_bounds) = within_bounds else {
        return Ok(None);
    };
    if !within_bounds {
        return Err(SyncError::PayloadTooLarge("sync_vault_too_large"));
    }

    VaultRepo::new(pool)
        .get_by_id(vault_id)
        .await
        .map_err(|err| {
            tracing::error!(event = "sync_vault_load_failed", error = %err, "DB error");
            SyncError::DbError
        })
}

fn decrypt_shared_typed_payload(
    vault_key: &SecretKey,
    vault_id: uuid::Uuid,
    item_id: uuid::Uuid,
    payload_enc: &[u8],
    type_id: &str,
) -> Result<EncryptedPayload, SyncError> {
    let payload = if type_id == SECRET_TYPE_ID {
        let bytes = core_crypto::decrypt_payload_bytes(vault_key, vault_id, item_id, payload_enc)
            .map_err(|_| SyncError::Internal("payload_decrypt_failed"))?;
        // Ownership is transferred so the compatibility decoder can zero-fill
        // this exact plaintext allocation on every return path.
        decode_secret_payload_bytes(bytes)
            .map_err(|_| SyncError::Internal("invalid_typed_payload"))?
    } else {
        core_crypto::decrypt_payload(vault_key, vault_id, item_id, payload_enc)
            .map_err(|_| SyncError::Internal("payload_decrypt_failed"))?
    };
    validate_server_typed_payload(&payload, type_id)
        .map_err(|_| SyncError::Internal("invalid_typed_payload"))?;
    Ok(payload)
}

pub(crate) async fn prepare_sync(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    action: &str,
    resource: &str,
) -> Result<SyncPrep, SyncPrepError> {
    let device_id = identity.device_id.ok_or(SyncPrepError::DeviceRequired)?;

    let vault = match fetch_bounded_sync_vault(&state.db, vault_id).await? {
        Some(vault) => vault,
        None => return Err(SyncPrepError::NotFound),
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
            return Err(SyncPrepError::ForbiddenNoBody);
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
                    return Err(SyncPrepError::ForbiddenNoBody);
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
    let prep = prepare_sync(state, identity, vault_id, "read", resource).await?;
    let vault = prep.vault;

    let since_seq = match decode_cursor(cursor) {
        Ok(seq) => seq,
        Err(error) => return Err(SyncError::BadRequest(error.error)),
    };

    let limit = clamp_pull_limit(limit);
    let rows = fetch_sync_page(&state.db, vault.id, since_seq, limit).await?;
    let (has_more, next_seq) = page_state(&rows, since_seq, |row| row.seq, |row| row.has_more);

    let mut changes = Vec::with_capacity(rows.len());
    for mut row in rows {
        let seq = row.seq;
        let op =
            ChangeOp::try_from(row.op).map_err(|_| SyncError::BadRequest("invalid_operation"))?;
        let (path, name, type_id, checksum) = take_bounded_item_fields(&mut row)?;
        let payload_enc = if op == ChangeOp::Delete {
            None
        } else {
            Some(
                row.payload_enc
                    .take()
                    .ok_or(SyncError::Internal("invalid_sync_row"))?,
            )
        };
        let history = fetch_sync_history(&state.db, row.item_id)
            .await?
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
            count = history.len()
        );
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
            checksum,
            payload_enc,
            path,
            name,
            type_id,
            history,
        });
    }

    ensure_response_budget(&changes)?;
    let next_cursor = encode_cursor(next_seq);
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

    let vault = match fetch_bounded_sync_vault(&state.db, vault_id).await? {
        Some(vault) => vault,
        None => return Err(SyncError::NotFound),
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
            return Err(SyncError::ForbiddenNoBody);
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
                    return Err(SyncError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SyncError::DbError);
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
    let limit = clamp_pull_limit(limit);
    let rows = fetch_sync_page(&state.db, vault.id, since_seq, limit).await?;
    let (has_more, next_seq) = page_state(&rows, since_seq, |row| row.seq, |row| row.has_more);

    let mut changes = Vec::with_capacity(rows.len());
    for mut row in rows {
        let seq = row.seq;
        let op =
            ChangeOp::try_from(row.op).map_err(|_| SyncError::BadRequest("invalid_operation"))?;
        let (path, name, type_id, checksum) = take_bounded_item_fields(&mut row)?;
        let payload = if op == ChangeOp::Delete {
            None
        } else {
            let payload_enc = row
                .payload_enc
                .take()
                .ok_or(SyncError::Internal("invalid_sync_row"))?;
            Some(decrypt_shared_typed_payload(
                &vault_key,
                vault.id,
                row.item_id,
                &payload_enc,
                &type_id,
            )?)
        };
        let history_rows = fetch_sync_history(&state.db, row.item_id).await?;
        let mut history = Vec::with_capacity(history_rows.len());
        for entry in history_rows {
            let payload = decrypt_shared_typed_payload(
                &vault_key,
                vault.id,
                row.item_id,
                &entry.payload_enc,
                &type_id,
            )?;
            history.push(SyncSharedHistoryEntry {
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
            count = history.len()
        );
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
            checksum,
            payload,
            path,
            name,
            type_id,
            history,
        });
    }

    ensure_response_budget(&changes)?;
    let next_cursor = encode_cursor(next_seq);
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
    validate_push_change_count(changes.len())?;
    validate_push_base_sequences(
        changes
            .iter()
            .map(|change| (change.operation, change.base_seq)),
    )?;
    let resource = "sync/push";
    let prep = prepare_sync(state, identity, vault_id, "write", resource).await?;
    let vault = prep.vault;
    let device_id = prep.device_id;

    let mut applied = Vec::new();
    let mut applied_changes = Vec::new();
    let mut conflicts = Vec::new();

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(event = "sync_push_failed", error = %err, "DB begin failed");
            return Err(SyncError::DbError);
        }
    };
    if let Err(err) = apply_tx_isolation(&mut tx, state.db_tx_isolation).await {
        tracing::error!(event = "sync_push_failed", error = %err, "DB begin failed");
        return Err(SyncError::DbError);
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
                    return Err(SyncError::DbError);
                }
                return match err.status {
                    axum::http::StatusCode::BAD_REQUEST => Err(SyncError::BadRequest(err.error)),
                    axum::http::StatusCode::PAYLOAD_TOO_LARGE => {
                        Err(SyncError::PayloadTooLarge(err.error))
                    }
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
            return Err(SyncError::DbError);
        }
        return Ok(SyncPushResult {
            applied: Vec::new(),
            applied_changes: Vec::new(),
            conflicts,
            // Deprecated wire field: a push proves no pull visibility. Zero
            // forces legacy consumers to perform a full current snapshot.
            new_cursor: encode_cursor(0),
        });
    }

    if let Err(err) = tx.commit().await {
        tracing::error!(event = "sync_push_failed", error = %err, "DB commit failed");
        return Err(SyncError::DbError);
    }

    Ok(SyncPushResult {
        applied,
        applied_changes,
        conflicts,
        // Never expose a server head as a pull cursor. Intervening changes may
        // exist that this request did not observe, even after a successful push.
        new_cursor: encode_cursor(0),
    })
}

pub(crate) async fn sync_shared_push(
    state: &AppState,
    identity: &Identity,
    vault_id: uuid::Uuid,
    changes: Vec<SyncSharedPushChange>,
) -> Result<SyncPushResult, SyncError> {
    validate_push_change_count(changes.len())?;
    validate_push_base_sequences(
        changes
            .iter()
            .map(|change| (change.operation, change.base_seq)),
    )?;
    let resource = "sync/shared/push";
    let policies = state.policy_store.get();

    let _device_id = identity.device_id.ok_or(SyncError::DeviceRequired)?;

    let vault = match fetch_bounded_sync_vault(&state.db, vault_id).await? {
        Some(vault) => vault,
        None => return Err(SyncError::NotFound),
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
            return Err(SyncError::ForbiddenNoBody);
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
                    return Err(SyncError::ForbiddenNoBody);
                }
                Err(_) => {
                    tracing::error!(event = "vault_access_failed", "DB error");
                    return Err(SyncError::DbError);
                }
            }
        }
    }

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
        let type_id =
            canonical_type_id(type_id).map_err(|error| SyncError::BadRequest(error.code()))?;
        validate_server_typed_payload(&payload, &type_id)
            .map_err(|error| SyncError::BadRequest(error.code()))?;
        let payload_enc =
            match core_crypto::encrypt_payload(&vault_key, vault.id, change.item_id, &payload) {
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
            type_id: Some(type_id),
            base_seq: change.base_seq,
        });
    }

    sync_push(state, identity, vault_id, payload_changes).await
}

fn validate_push_base_sequences(
    changes: impl IntoIterator<Item = (ChangeType, Option<i64>)>,
) -> Result<(), SyncError> {
    for (operation, base_seq) in changes {
        match (operation, base_seq) {
            (ChangeType::Create, None) => {}
            (ChangeType::Create, Some(_)) => {
                return Err(SyncError::BadRequest("unexpected_base_seq"));
            }
            (ChangeType::Update | ChangeType::Restore | ChangeType::Delete, Some(seq))
                if seq > 0 => {}
            (ChangeType::Update | ChangeType::Restore | ChangeType::Delete, _) => {
                return Err(SyncError::BadRequest("base_seq_required"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        clamp_pull_limit, page_state, validate_push_base_sequences, validate_push_change_count,
        SYNC_PULL_PAGE_LIMIT,
    };
    use zann_core::ChangeType;

    #[test]
    fn bounded_change_page_honors_limit_and_advances_to_last_returned_sequence() {
        let rows = [(11_i64, true), (12, true)];

        let (has_more, next_seq) =
            page_state(&rows, 10, |(sequence, _)| *sequence, |(_, more)| *more);

        assert!(has_more);
        assert_eq!(next_seq, 12);
    }

    #[test]
    fn bounded_change_page_preserves_cursor_for_an_empty_page() {
        let rows: Vec<(i64, bool)> = Vec::new();

        let (has_more, next_seq) =
            page_state(&rows, 37, |(sequence, _)| *sequence, |(_, more)| *more);

        assert!(!has_more);
        assert_eq!(next_seq, 37);
    }

    #[test]
    fn pull_limit_is_bounded_for_personal_and_shared_pages() {
        assert_eq!(clamp_pull_limit(0), 1);
        assert_eq!(clamp_pull_limit(2), 2);
        assert_eq!(clamp_pull_limit(250), SYNC_PULL_PAGE_LIMIT);
        assert_eq!(clamp_pull_limit(500), SYNC_PULL_PAGE_LIMIT);
    }

    #[test]
    fn push_batch_limit_is_checked_before_service_work() {
        assert!(validate_push_change_count(64).is_ok());
        assert!(matches!(
            validate_push_change_count(65),
            Err(super::SyncError::BadRequest("too_many_changes"))
        ));
    }

    #[test]
    fn push_base_sequence_shape_is_fail_closed() {
        assert!(validate_push_base_sequences([(ChangeType::Create, None)]).is_ok());
        assert!(validate_push_base_sequences([(ChangeType::Update, Some(1))]).is_ok());
        for invalid in [
            (ChangeType::Create, Some(1)),
            (ChangeType::Update, None),
            (ChangeType::Restore, Some(0)),
            (ChangeType::Delete, Some(-1)),
        ] {
            assert!(validate_push_base_sequences([invalid]).is_err());
        }
    }
}
