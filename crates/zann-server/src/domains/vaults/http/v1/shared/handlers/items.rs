use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use sqlx_core::types::Json as SqlxJson;
use uuid::Uuid;
use zann_core::{Change, ChangeOp, ChangeType, Identity, Item, ItemHistory, SyncStatus};
use zann_crypto::vault_crypto as core_crypto;
use zann_db::repo::{AttachmentRepo, ChangeRepo, ItemHistoryRepo, ItemRepo, VaultRepo};

use crate::app::AppState;
use crate::domains::access_control::http::{find_vault, vault_role_allows, VaultScope};
use crate::domains::items::contract::{
    canonical_create_location, canonical_type_id, canonical_update_location, next_item_version,
    serialized_typed_payload_len, validate_existing_type_id, validate_server_typed_payload,
    MAX_CIPHERTEXT_BYTES,
};
use crate::domains::items::service::{self as item_service, ITEM_HISTORY_LIMIT};
use crate::infra::metrics;

use super::super::helpers::{
    actor_snapshot, effective_device_id, evaluate_history_policy, is_shared_server_vault,
    normalize_path, service_account_allows_path, service_account_allows_prefix,
};
use super::super::types::{
    CreateSharedItemRequest, ErrorResponse, HistoryListQuery, ItemHistoryDetailResponse,
    ItemHistoryListResponse, ItemHistorySummary, SharedItemResponse, SharedItemsQuery,
    SharedItemsResponse, UpdateSharedItemRequest,
};
use super::super::HISTORY_LIMIT;

const SHARED_LIST_LIMIT: i64 = 4;
const SHARED_LIST_RESPONSE_BUDGET: usize = 2 * 1024 * 1024;

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

    let cursor = match item_service::parse_item_list_cursor(query.cursor.as_deref()) {
        Ok(cursor) => cursor,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_cursor",
                }),
            )
                .into_response();
        }
    };

    let limit = query
        .limit
        .unwrap_or(SHARED_LIST_LIMIT)
        .clamp(1, SHARED_LIST_LIMIT);
    let page = match item_service::fetch_item_list_page(
        &state,
        vault.id,
        prefix.as_deref(),
        cursor,
        limit,
    )
    .await
    {
        Ok(page) => page,
        Err(_) => {
            tracing::error!(event = "shared_items_list_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let mut response_items = Vec::with_capacity(page.items.len());
    let mut response_bytes = 0_usize;
    for item in &page.items {
        let payload_enc = match item_service::fetch_current_item_payload(
            &state,
            item,
            MAX_CIPHERTEXT_BYTES,
        )
        .await
        {
            Ok(payload) => payload,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "invalid_payload",
                    }),
                )
                    .into_response();
            }
        };
        let payload = match item_service::decrypt_typed_payload(
            &state,
            &vault,
            item.id,
            &payload_enc,
            &item.type_id,
        ) {
            Ok(payload) => payload,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "invalid_typed_payload",
                    }),
                )
                    .into_response();
            }
        };
        let payload_bytes = match serialized_typed_payload_len(&payload) {
            Ok(payload_bytes) => payload_bytes,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "invalid_typed_payload",
                    }),
                )
                    .into_response();
            }
        };
        response_bytes = response_bytes.saturating_add(payload_bytes);
        if response_bytes > SHARED_LIST_RESPONSE_BUDGET {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorResponse {
                    error: "response_too_large",
                }),
            )
                .into_response();
        }
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
            next_cursor: if page.has_more {
                page.items.last().map(item_service::encode_item_list_cursor)
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
    if item.sync_status != SyncStatus::Active || item.deleted_at.is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }

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

    let payload = match item_service::decrypt_typed_payload(
        &state,
        &vault,
        item.id,
        &item.payload_enc,
        &item.type_id,
    ) {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "invalid_typed_payload",
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
                change_type: history.change_type,
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

    let payload = match item_service::decrypt_typed_payload(
        &state,
        &vault,
        item.id,
        &history.payload_enc,
        &item.type_id,
    ) {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "invalid_typed_payload",
                }),
            )
                .into_response();
        }
    };

    let response = ItemHistoryDetailResponse {
        version: history.version,
        checksum: history.checksum,
        payload,
        change_type: history.change_type,
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

pub(crate) async fn create_shared_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(req): Json<CreateSharedItemRequest>,
) -> impl IntoResponse {
    let resource = "shared/items/create";
    let (path, name) = match canonical_create_location(&req.path, None) {
        Ok(location) => location,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: error.code(),
                }),
            )
                .into_response();
        }
    };
    let type_id = match canonical_type_id(&req.type_id) {
        Ok(type_id) => type_id,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: error.code(),
                }),
            )
                .into_response();
        }
    };
    if let Err(error) = validate_server_typed_payload(&req.payload, &type_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.code(),
            }),
        )
            .into_response();
    }
    let policies = state.policy_store.get();

    let vault_repo = VaultRepo::new(&state.db);
    let vault = match find_vault(&vault_repo, &req.vault_id).await {
        Ok(Some(vault)) => vault,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_item_create_failed", "DB error");
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

    // Authorization
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(&state, service_account_id, &vault, "write", &path).await {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match policies.evaluate(&identity, "write", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(&state, &identity, vault.id, "write", VaultScope::Items)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_item_create_failed", "DB error");
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
    let item_id = Uuid::now_v7();

    let smk = match state.server_master_key.as_ref() {
        Some(value) => value.as_ref(),
        None => {
            tracing::error!(event = "shared_item_create_failed", "SMK not configured");
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
        Err(err) => {
            tracing::error!(event = "shared_item_create_failed", error = %err, "Key decrypt failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let payload_enc = match core_crypto::encrypt_payload(
        &vault_key,
        vault.id,
        item_id,
        &req.payload,
    ) {
        Ok(enc) => enc,
        Err(err) => {
            tracing::error!(event = "shared_item_create_failed", error = %err, "Encryption failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "encrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let checksum = core_crypto::payload_checksum(&payload_enc);

    let tags = req
        .tags
        .map(|tags| {
            tags.into_iter()
                .filter(|t| !t.trim().is_empty())
                .take(crate::domains::items::service::MAX_TAGS)
                .collect::<Vec<_>>()
        })
        .filter(|tags| !tags.is_empty());

    let device_id = match effective_device_id(&state, &identity).await {
        Ok(device_id) => device_id,
        Err("device_required") => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "device_required",
                }),
            )
                .into_response();
        }
        Err(_) => {
            tracing::error!(event = "shared_item_create_failed", "Device lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let now = Utc::now();
    let item = Item {
        id: item_id,
        vault_id: vault.id,
        path: path.clone(),
        name: name.clone(),
        type_id: type_id.clone(),
        tags: tags.clone().map(SqlxJson),
        favorite: req.favorite.unwrap_or(false),
        payload_enc: payload_enc.clone(),
        checksum: checksum.clone(),
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

    let actor = actor_snapshot(&state, &identity, identity.device_id).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id,
        payload_enc,
        checksum: checksum.clone(),
        version: 1,
        change_type: ChangeType::Create,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: identity.device_id,
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id,
        op: ChangeOp::Create,
        version: 1,
        device_id,
        created_at: now,
    };
    let item_repo = ItemRepo::new(&state.db);
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(event = "shared_item_create_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if let Err(err) = item_repo.create_in(&mut tx, &item).await {
        tracing::error!(event = "shared_item_create_failed", error = %err, "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = history_repo.create_in(&mut tx, &history).await {
        tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
    {
        tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = change_repo.create_in(&mut tx, &change).await {
        tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(event = "shared_item_create_commit_failed", error = %err, item_id = %item_id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    tracing::info!(event = "shared_item_created", item_id = %item_id, path = %path);
    (
        StatusCode::CREATED,
        Json(SharedItemResponse {
            id: item_id.to_string(),
            vault_id: vault.id.to_string(),
            path,
            name,
            type_id,
            tags,
            favorite: req.favorite.unwrap_or(false),
            payload: req.payload,
            checksum,
            version: 1,
            deleted_at: None,
            updated_at: now.to_rfc3339(),
        }),
    )
        .into_response()
}

pub(crate) async fn update_shared_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
    Json(req): Json<UpdateSharedItemRequest>,
) -> impl IntoResponse {
    let resource = "shared/items/update";
    let policies = state.policy_store.get();

    let item_repo = ItemRepo::new(&state.db);
    let mut item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_item_update_failed", "DB error");
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
    if item.sync_status != SyncStatus::Active {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (next_path, next_name) =
        match canonical_update_location(&item.path, req.path.as_deref(), None) {
            Ok(location) => location,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: error.code(),
                    }),
                )
                    .into_response();
            }
        };
    if let Err(error) = validate_existing_type_id(&item.type_id, req.type_id.as_deref()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.code(),
            }),
        )
            .into_response();
    }
    if let Err(error) = validate_server_typed_payload(&req.payload, &item.type_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: error.code(),
            }),
        )
            .into_response();
    }

    // Authorization
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(&state, service_account_id, &vault, "write", &item.path)
            .await
            || !service_account_allows_path(&state, service_account_id, &vault, "write", &next_path)
                .await
        {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match policies.evaluate(&identity, "write", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(&state, &identity, vault.id, "write", VaultScope::Items)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_item_update_failed", "DB error");
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

    let previous_payload_enc = item.payload_enc.clone();
    let previous_checksum = item.checksum.clone();
    let previous_version = item.version;

    item.path = next_path;
    item.name = next_name;

    // Update tags
    if let Some(tags) = req.tags {
        let tags: Vec<String> = tags
            .into_iter()
            .filter(|t| !t.trim().is_empty())
            .take(crate::domains::items::service::MAX_TAGS)
            .collect();
        item.tags = if tags.is_empty() {
            None
        } else {
            Some(SqlxJson(tags))
        };
    }

    // Update favorite
    if let Some(favorite) = req.favorite {
        item.favorite = favorite;
    }

    let smk = match state.server_master_key.as_ref() {
        Some(value) => value.as_ref(),
        None => {
            tracing::error!(event = "shared_item_update_failed", "SMK not configured");
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
        Err(err) => {
            tracing::error!(event = "shared_item_update_failed", error = %err, "Key decrypt failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "decrypt_failed",
                }),
            )
                .into_response();
        }
    };
    let payload_enc = match core_crypto::encrypt_payload(
        &vault_key,
        vault.id,
        item.id,
        &req.payload,
    ) {
        Ok(enc) => enc,
        Err(err) => {
            tracing::error!(event = "shared_item_update_failed", error = %err, "Encryption failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "encrypt_failed",
                }),
            )
                .into_response();
        }
    };
    item.payload_enc = payload_enc;
    item.checksum = core_crypto::payload_checksum(&item.payload_enc);

    // History entry for previous version
    let actor = actor_snapshot(&state, &identity, identity.device_id).await;
    let history = ItemHistory {
        id: Uuid::now_v7(),
        item_id: item.id,
        payload_enc: previous_payload_enc,
        checksum: previous_checksum,
        version: previous_version,
        change_type: ChangeType::Update,
        fields_changed: None,
        changed_by_user_id: identity.user_id,
        changed_by_email: actor.email,
        changed_by_name: actor.name,
        changed_by_device_id: identity.device_id,
        changed_by_device_name: actor.device_name,
        created_at: Utc::now(),
    };

    let device_id = match effective_device_id(&state, &identity).await {
        Ok(device_id) => device_id,
        Err("device_required") => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "device_required",
                }),
            )
                .into_response();
        }
        Err(_) => {
            tracing::error!(event = "shared_item_update_failed", "Device lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    item.version = match next_item_version(item.version) {
        Ok(version) => version,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "invalid_version",
                }),
            )
                .into_response();
        }
    };
    item.device_id = device_id;
    item.updated_at = Utc::now();

    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Update,
        version: item.version,
        device_id,
        created_at: item.updated_at,
    };
    let history_repo = ItemHistoryRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(event = "shared_item_update_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let locked = match item_repo.get_by_id_for_update_in(&mut tx, item.id).await {
        Ok(Some(locked)) => locked,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(event = "shared_item_update_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if locked.vault_id != vault.id || locked.row_version != item.row_version {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "version_conflict",
            }),
        )
            .into_response();
    }
    if let Err(err) = history_repo.create_in(&mut tx, &history).await {
        tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
    {
        tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    let affected = match item_repo.update_in(&mut tx, &item).await {
        Ok(affected) => affected,
        Err(err) => {
            tracing::error!(event = "shared_item_update_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if affected != 1 {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "version_conflict",
            }),
        )
            .into_response();
    }
    if let Err(err) = change_repo.create_in(&mut tx, &change).await {
        tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(event = "shared_item_update_commit_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    tracing::info!(event = "shared_item_updated", item_id = %item.id, path = %item.path);

    (
        StatusCode::OK,
        Json(SharedItemResponse {
            id: item.id.to_string(),
            vault_id: vault.id.to_string(),
            path: item.path,
            name: item.name,
            type_id: item.type_id,
            tags: item.tags.map(|t| t.0),
            favorite: item.favorite,
            payload: req.payload,
            checksum: item.checksum,
            version: item.version,
            deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
            updated_at: item.updated_at.to_rfc3339(),
        }),
    )
        .into_response()
}

pub(crate) async fn delete_shared_item(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(item_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = "shared/items/delete";
    let policies = state.policy_store.get();

    let item_repo = ItemRepo::new(&state.db);
    let mut item = match item_repo.get_by_id(item_id).await {
        Ok(Some(item)) => item,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "shared_item_delete_failed", "DB error");
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
    if item.sync_status != SyncStatus::Active {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Authorization
    if let Some(service_account_id) = identity.service_account_id {
        if !service_account_allows_path(&state, service_account_id, &vault, "write", &item.path)
            .await
        {
            metrics::forbidden_access(resource);
            return StatusCode::FORBIDDEN.into_response();
        }
    } else {
        match policies.evaluate(&identity, "write", resource) {
            crate::domains::access_control::policies::PolicyDecision::Allow => {}
            crate::domains::access_control::policies::PolicyDecision::Deny => {
                metrics::forbidden_access(resource);
                return StatusCode::FORBIDDEN.into_response();
            }
            crate::domains::access_control::policies::PolicyDecision::NoMatch => {
                match vault_role_allows(&state, &identity, vault.id, "write", VaultScope::Items)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        metrics::forbidden_access(resource);
                        return StatusCode::FORBIDDEN.into_response();
                    }
                    Err(_) => {
                        tracing::error!(event = "shared_item_delete_failed", "DB error");
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

    let device_id = match effective_device_id(&state, &identity).await {
        Ok(device_id) => device_id,
        Err("device_required") => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "device_required",
                }),
            )
                .into_response();
        }
        Err(_) => {
            tracing::error!(event = "shared_item_delete_failed", "Device lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let now = Utc::now();

    let actor = actor_snapshot(&state, &identity, identity.device_id).await;
    let history = ItemHistory {
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
        changed_by_device_id: identity.device_id,
        changed_by_device_name: actor.device_name,
        created_at: now,
    };
    // Soft delete
    item.sync_status = SyncStatus::Tombstone;
    item.deleted_at = Some(now);
    item.deleted_by_user_id = Some(identity.user_id);
    item.deleted_by_device_id = Some(device_id);
    item.version = match next_item_version(item.version) {
        Ok(version) => version,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "invalid_version",
                }),
            )
                .into_response();
        }
    };
    item.device_id = device_id;
    item.updated_at = now;

    let change = Change {
        seq: 0,
        vault_id: vault.id,
        item_id: item.id,
        op: ChangeOp::Delete,
        version: item.version,
        device_id,
        created_at: now,
    };
    let history_repo = ItemHistoryRepo::new(&state.db);
    let attachment_repo = AttachmentRepo::new(&state.db);
    let change_repo = ChangeRepo::new(&state.db);
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(err) => {
            tracing::error!(event = "shared_item_delete_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    let locked = match item_repo.get_by_id_for_update_in(&mut tx, item.id).await {
        Ok(Some(locked)) => locked,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(event = "shared_item_delete_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if locked.vault_id != vault.id || locked.row_version != item.row_version {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "version_conflict",
            }),
        )
            .into_response();
    }
    if let Err(err) = history_repo.create_in(&mut tx, &history).await {
        tracing::error!(event = "item_history_create_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = history_repo
        .prune_by_item_in(&mut tx, item.id, ITEM_HISTORY_LIMIT)
        .await
    {
        tracing::error!(event = "item_history_prune_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = attachment_repo
        .mark_deleted_by_item_in(&mut tx, item.id, now)
        .await
    {
        tracing::error!(event = "item_attachment_mark_deleted_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    let affected = match item_repo.update_in(&mut tx, &item).await {
        Ok(affected) => affected,
        Err(err) => {
            tracing::error!(event = "shared_item_delete_failed", error = %err, "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };
    if affected != 1 {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "version_conflict",
            }),
        )
            .into_response();
    }
    if let Err(err) = change_repo.create_in(&mut tx, &change).await {
        tracing::error!(event = "item_change_create_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }
    if let Err(err) = tx.commit().await {
        tracing::error!(event = "shared_item_delete_commit_failed", error = %err, item_id = %item.id);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    tracing::info!(event = "shared_item_deleted", item_id = %item.id, path = %item.path);
    StatusCode::NO_CONTENT.into_response()
}
