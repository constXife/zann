use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use zann_core::vault_crypto as core_crypto;
use zann_core::Identity;
use zann_db::repo::{ItemHistoryRepo, ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{find_vault, vault_role_allows, VaultScope};
use crate::infra::metrics;

use super::super::helpers::{
    cursor_allows, encode_cursor, evaluate_history_policy, is_shared_server_vault, normalize_path,
    parse_cursor, prefix_match, service_account_allows_path, service_account_allows_prefix,
};
use super::super::types::{
    ErrorResponse, HistoryListQuery, ItemHistoryDetailResponse, ItemHistoryListResponse,
    ItemHistorySummary, SharedItemResponse, SharedItemsQuery, SharedItemsResponse,
};
use super::super::HISTORY_LIMIT;

pub(crate) async fn list_shared_items(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(query): Query<SharedItemsQuery>,
) -> impl IntoResponse {
    let resource = "shared/items";
    let policies = state.policy_store.get();

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&vault_repo, &query.vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_items_list_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if !is_shared_server_vault(&vault) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let prefix = query
        .prefix
        .as_deref()
        .map(normalize_path)
        .filter(|value| !value.is_empty());
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_prefix(
            &state,
            service_account_id,
            &vault,
            "list",
            prefix.as_deref(),
        )
        .await
        {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match policies.evaluate(&identity, "list", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(&state, &identity, vault.id, "list", VaultScope::Items)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_items_list_failed", "DB error");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { error: "db_error" }),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    let item_repo = ItemRepo::new(&state.db);
    let items = match item_repo.list_by_vault(vault.id, false).await {
        Ok(items) => items,
        Err(_) => {
            tracing::error!(event = "shared_items_list_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let limit = query.limit.unwrap_or(100).clamp(1, 500) as usize;
    let cursor = query.cursor.as_deref().and_then(parse_cursor);

    let mut filtered = items
        .into_iter()
        .filter(|item| prefix_match(prefix.as_deref(), &item.path))
        .collect::<Vec<_>>();
    filtered.sort_by(|a, b| {
        b.updated_at
            .cmp(&a.updated_at)
            .then_with(|| b.id.cmp(&a.id))
    });
    let mut page = Vec::new();
    let mut has_more = false;
    for item in filtered.into_iter() {
        if !cursor_allows(cursor.as_ref(), &item) {
            continue;
        }
        if page.len() >= limit {
            has_more = true;
            break;
        }
        page.push(item);
    }

    let smk = match state.server_master_key.as_ref() {
        Some(value) => value.as_ref(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_key_missing",
                }),
            )
                .into_response();
        }
    };
    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };

    let mut response_items = Vec::with_capacity(page.len());
    for item in page.iter() {
        let payload_bytes = match core_crypto::decrypt_payload_bytes(
            &vault_key,
            vault.id,
            item.id,
            &item.payload_enc,
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "decrypt_failed",
                    }),
                )
                    .into_response();
            }
        };
        let payload = match serde_json::from_slice(&payload_bytes) {
            Ok(payload) => payload,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "decrypt_failed",
                    }),
                )
                    .into_response();
            }
        };
        response_items.push(SharedItemResponse {
            id: item.id.to_string(),
            vault_id: item.vault_id.to_string(),
            path: item.path.clone(),
            name: item.name.clone(),
            type_id: item.type_id.clone(),
            tags: item.tags.as_ref().map(|tags| tags.0.clone()),
            favorite: item.favorite,
            payload,
            checksum: item.checksum.clone(),
            version: item.version,
            deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
            updated_at: item.updated_at.to_rfc3339(),
        });
    }

    (
        StatusCode::OK,
        Json(SharedItemsResponse {
            items: response_items,
            next_cursor: if has_more {
                page.last().map(encode_cursor)
            } else {
                None
            },
        }),
    )
        .into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn get_shared_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/get";
    let policies = state.policy_store.get();

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_item_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let vault_repo = VaultRepo::new(&state.db);
    let Some(vault) = vault_repo.get_by_id(item.vault_id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_shared_server_vault(&vault) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(&state, service_account_id, &vault, "read", &item.path)
            .await
        {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match policies.evaluate(&identity, "read", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(&state, &identity, vault.id, "read", VaultScope::Items)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_item_get_failed", "DB error");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { error: "db_error" }),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    let smk = match state.server_master_key.as_ref() {
        Some(value) => value.as_ref(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_key_missing",
                }),
            )
                .into_response();
        }
    };
    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let payload_bytes = match core_crypto::decrypt_payload_bytes(
        &vault_key,
        vault.id,
        item.id,
        &item.payload_enc,
    ) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let payload = match serde_json::from_slice(&payload_bytes) {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(SharedItemResponse {
            id: item.id.to_string(),
            vault_id: item.vault_id.to_string(),
            path: item.path,
            name: item.name,
            type_id: item.type_id,
            tags: item.tags.map(|tags| tags.0),
            favorite: item.favorite,
            payload,
            checksum: item.checksum,
            version: item.version,
            deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
            updated_at: item.updated_at.to_rfc3339(),
        }),
    )
        .into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id))]

pub(crate) async fn list_shared_versions(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
    Query(query): Query<HistoryListQuery>,
) -> impl IntoResponse {
    let resource = "shared/items/versions";
    let policies = state.policy_store.get();

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_versions_list_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let vault_repo = VaultRepo::new(&state.db);
    let Some(vault) = vault_repo.get_by_id(item.vault_id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_shared_server_vault(&vault) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(
            &state,
            service_account_id,
            &vault,
            "read_history",
            &item.path,
        )
        .await
        {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match evaluate_history_policy(&policies, &identity, "read_history", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(
                    &state,
                    &identity,
                    vault.id,
                    "read_history",
                    VaultScope::Items,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_versions_list_failed", "DB error");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { error: "db_error" }),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    let limit = query.limit.unwrap_or(HISTORY_LIMIT).clamp(1, HISTORY_LIMIT);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let versions = match history_repo.list_by_item_limit(item.id, limit).await {
        Ok(rows) => rows
            .into_iter()
            .map(|history| ItemHistorySummary {
                version: history.version,
                checksum: history.checksum,
                change_type: history.change_type.as_str().to_string(),
                changed_by_name: history.changed_by_name,
                changed_by_email: history.changed_by_email,
                created_at: history.created_at.to_rfc3339(),
            })
            .collect(),
        Err(_) => {
            tracing::error!(event = "shared_versions_list_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    tracing::info!(
        event = "item.view_history_list",
        item_id = %item.id,
        vault_id = %vault.id,
        path = %item.path,
        actor_id = %identity.user_id,
        service_account_id = ?identity.service_account_id,
        "History list viewed"
    );
    (StatusCode::OK, Json(ItemHistoryListResponse { versions })).into_response()
}

#[tracing::instrument(skip(state, identity), fields(item_id = %item_id, version = %version))]

pub(crate) async fn get_shared_version(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((item_id, version)): axum::extract::Path<(Uuid, i64)>,
) -> impl IntoResponse {
    let resource = "shared/items/versions/get";
    let policies = state.policy_store.get();

    let item_repo = ItemRepo::new(&state.db);
    let item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_version_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let vault_repo = VaultRepo::new(&state.db);
    let Some(vault) = vault_repo.get_by_id(item.vault_id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !is_shared_server_vault(&vault) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(
            &state,
            service_account_id,
            &vault,
            "read_previous",
            &item.path,
        )
        .await
        {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match evaluate_history_policy(&policies, &identity, "read_previous", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(
                    &state,
                    &identity,
                    vault.id,
                    "read_previous",
                    VaultScope::Items,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_version_get_failed", "DB error");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse { error: "db_error" }),
                        )
                            .into_response();
                    }
                }
            }
        }
    }

    let history_repo = ItemHistoryRepo::new(&state.db);
    let history = match history_repo.get_by_item_version(item.id, version).await {
        Ok(Some(history)) => history,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_version_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let smk = match state.server_master_key.as_ref() {
        Some(value) => value.as_ref(),
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_key_missing",
                }),
            )
                .into_response();
        }
    };
    let vault_key = match core_crypto::decrypt_vault_key(smk, vault.id, &vault.vault_key_enc) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let payload_bytes = match core_crypto::decrypt_payload_bytes(
        &vault_key,
        vault.id,
        item.id,
        &history.payload_enc,
    ) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let payload = match serde_json::from_slice(&payload_bytes) {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };

    let response = ItemHistoryDetailResponse {
        version: history.version,
        checksum: history.checksum,
        payload,
        change_type: history.change_type.as_str().to_string(),
        created_at: history.created_at.to_rfc3339(),
    };
    tracing::info!(
        event = "item.read_previous",
        item_id = %item.id,
        vault_id = %vault.id,
        path = %item.path,
        version_rev = version,
        actor_id = %identity.user_id,
        service_account_id = ?identity.service_account_id,
        "History version read"
    );
    (StatusCode::OK, Json(response)).into_response()
}
