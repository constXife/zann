use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx_core::from_row::FromRow;
use sqlx_core::row::Row;
use sqlx_postgres::{PgConnection, PgRow};
use uuid::Uuid;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;

use super::types::{ErrorResponse, SyncCursor, SyncPullRow};

pub(super) async fn find_path_conflict(
    conn: &mut PgConnection,
    vault_id: Uuid,
    path: &str,
    exclude_id: Option<Uuid>,
) -> Result<Option<String>, sqlx_core::Error> {
    let row = query!(
        r#"
        SELECT updated_at
        FROM items
        WHERE vault_id = $1
          AND path = $2
          AND sync_status = 1
          AND ($3::uuid IS NULL OR id <> $3)
        LIMIT 1
        "#,
        vault_id,
        path,
        exclude_id
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.and_then(|row| {
        row.try_get::<DateTime<Utc>, _>("updated_at")
            .ok()
            .map(|value| value.to_rfc3339())
    }))
}

impl FromRow<'_, PgRow> for SyncPullRow {
    fn from_row(row: &PgRow) -> Result<Self, sqlx_core::Error> {
        let op: i16 = row.try_get("op")?;
        Ok(Self {
            seq: row.try_get("seq")?,
            op: i32::from(op),
            item_id: row.try_get("item_id")?,
            path: row.try_get("path")?,
            name: row.try_get("name")?,
            type_id: row.try_get("type_id")?,
            payload_enc: row.try_get("payload_enc")?,
            checksum: row.try_get("checksum")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

pub(super) async fn prune_item_history(
    conn: &mut PgConnection,
    item_id: Uuid,
    keep: i64,
) -> Result<u64, sqlx_core::Error> {
    query!(
        r#"
        DELETE FROM item_history
        WHERE id IN (
            SELECT id
            FROM item_history
            WHERE item_id = $1
            ORDER BY version DESC
            OFFSET $2
        )
        "#,
        item_id,
        keep
    )
    .execute(&mut *conn)
    .await
    .map(|result| result.rows_affected())
}

pub(super) fn default_sync_limit() -> i64 {
    100
}

pub(crate) fn decode_cursor(cursor: Option<String>) -> Result<i64, ErrorResponse> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let decoded = match base64::engine::general_purpose::STANDARD.decode(cursor) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(ErrorResponse {
                error: "invalid_cursor",
            })
        }
    };
    let payload: SyncCursor = match serde_json::from_slice(&decoded) {
        Ok(payload) => payload,
        Err(_) => {
            return Err(ErrorResponse {
                error: "invalid_cursor",
            })
        }
    };
    Ok(payload.seq)
}

pub(crate) fn encode_cursor(seq: i64) -> String {
    let payload = SyncCursor { seq };
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(super) fn basename_from_path(path: &str) -> String {
    path.trim_matches('/')
        .split('/')
        .rfind(|part| !part.is_empty())
        .unwrap_or(path)
        .to_string()
}

pub(super) fn replace_basename(path: &str, name: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return name.to_string();
    }
    let mut parts: Vec<&str> = trimmed.split('/').collect();
    if let Some(last) = parts.last_mut() {
        *last = name;
    }
    parts.join("/")
}

pub(super) fn normalize_path_and_name(
    current_path: &str,
    new_path: Option<&str>,
    new_name: Option<&str>,
) -> (String, String) {
    let mut path = new_path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| current_path.to_string());
    if let Some(name) = new_name.map(str::trim).filter(|value| !value.is_empty()) {
        let clean = if name.contains('/') {
            basename_from_path(name)
        } else {
            name.to_string()
        };
        path = replace_basename(&path, &clean);
    }
    let name = basename_from_path(&path);
    (path, name)
}

pub(crate) fn parse_plaintext_payload(payload: &JsonValue) -> Result<Vec<u8>, ErrorResponse> {
    serde_json::to_vec(payload).map_err(|_| ErrorResponse {
        error: "invalid_payload",
    })
}

pub(crate) async fn can_push(state: &AppState, identity: &Identity, vault_id: Uuid) -> bool {
    let resource = "sync/push";
    let policies = state.policy_store.get();
    match policies.evaluate(identity, "write", resource) {
        PolicyDecision::Allow => true,
        PolicyDecision::Deny => false,
        PolicyDecision::NoMatch => {
            matches!(
                vault_role_allows(state, identity, vault_id, "write", VaultScope::Sync).await,
                Ok(true)
            )
        }
    }
}

pub(super) struct ActorSnapshot {
    pub(super) email: String,
    pub(super) name: Option<String>,
    pub(super) device_name: Option<String>,
}

pub(super) async fn actor_snapshot(
    conn: &mut PgConnection,
    identity: &Identity,
    device_id: Option<Uuid>,
) -> ActorSnapshot {
    let name = match query!(
        r"
        SELECT full_name
        FROM users
        WHERE id = $1 AND deleted_at IS NULL
        ",
        identity.user_id
    )
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(Some(row)) => row.try_get("full_name").ok(),
        _ => None,
    };

    let device_name = match device_id {
        Some(device_id) => {
            match query!(
                r"
                SELECT name
                FROM devices
                WHERE id = $1
                ",
                device_id
            )
            .fetch_optional(&mut *conn)
            .await
            {
                Ok(Some(row)) => row.try_get("name").ok(),
                _ => None,
            }
        }
        None => None,
    };

    ActorSnapshot {
        email: identity.email.clone(),
        name,
        device_name,
    }
}
