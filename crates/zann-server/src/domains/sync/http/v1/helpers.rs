use base64::Engine;
use chrono::{DateTime, Utc};
use sqlx_core::row::Row;
use sqlx_postgres::PgConnection;
use uuid::Uuid;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::access_control::http::{vault_role_allows, VaultScope};
use crate::domains::access_control::policies::PolicyDecision;

use super::types::{ErrorResponse, SyncCursor};

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
