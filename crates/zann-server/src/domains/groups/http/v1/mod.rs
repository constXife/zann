use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zann_core::{Group, GroupMember, Identity};
use zann_db::repo::{GroupMemberRepo, GroupRepo, UserRepo};

use crate::app::AppState;
use crate::infra::metrics;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ListGroupsQuery {
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct CreateGroupRequest {
    slug: String,
    name: String,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct UpdateGroupRequest {
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct AddMemberRequest {
    user_id: Uuid,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct GroupResponse {
    pub(crate) id: String,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) created_at: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct GroupListResponse {
    pub(crate) groups: Vec<GroupResponse>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct GroupMemberResponse {
    pub(crate) group_id: String,
    pub(crate) user_id: String,
    pub(crate) created_at: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/groups", get(list_groups).post(create_group))
        .route(
            "/v1/groups/:slug",
            get(get_group).put(update_group).delete(delete_group),
        )
        .route("/v1/groups/:slug/members", post(add_member))
        .route("/v1/groups/:slug/members/:user_id", delete(remove_member))
}

#[tracing::instrument(skip(state, identity, query))]
async fn list_groups(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(query): Query<ListGroupsQuery>,
) -> impl IntoResponse {
    let resource = "groups";
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "list", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "list",
            resource = resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let sort = query.sort.as_deref().unwrap_or("desc");

    let repo = GroupRepo::new(&state.db);
    let Ok(groups) = repo.list(limit, offset, sort).await else {
        tracing::error!(event = "groups_list_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };

    let groups: Vec<GroupResponse> = groups.into_iter().map(group_response).collect();
    tracing::info!(
        event = "groups_listed",
        count = groups.len(),
        "Groups listed"
    );
    (StatusCode::OK, Json(GroupListResponse { groups })).into_response()
}

#[tracing::instrument(skip(state, identity, payload))]
async fn create_group(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    let resource = "groups";
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "write", resource) {
        metrics::forbidden_access(resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let slug = payload.slug.trim();
    if slug.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_slug",
            }),
        )
            .into_response();
    }
    let name = payload.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_name",
            }),
        )
            .into_response();
    }

    let repo = GroupRepo::new(&state.db);
    match repo.get_by_slug(slug).await {
        Ok(Some(_)) => {
            tracing::warn!(
                event = "group_create_rejected",
                reason = "slug_taken",
                slug = %slug,
                "Group create rejected"
            );
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "slug_taken",
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(_) => {
            tracing::error!(event = "group_create_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let group = Group {
        id: Uuid::now_v7(),
        slug: slug.to_string(),
        name: name.to_string(),
        created_at: Utc::now(),
    };
    if repo.create(&group).await.is_err() {
        tracing::error!(event = "group_create_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    tracing::info!(
        event = "group_created",
        group_id = %group.id,
        slug = %group.slug,
        "Group created"
    );
    (StatusCode::CREATED, Json(group_response(group))).into_response()
}

#[tracing::instrument(skip(state, identity), fields(slug = %slug))]
async fn get_group(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> impl IntoResponse {
    let resource = format!("groups/{slug}");
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "read", &resource) {
        metrics::forbidden_access(&resource);
        tracing::warn!(
            event = "forbidden",
            action = "read",
            resource = %resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let repo = GroupRepo::new(&state.db);
    let group = match repo.get_by_slug(&slug).await {
        Ok(Some(group)) => group,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "group_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    tracing::info!(event = "group_fetched", slug = %slug, "Group fetched");
    (StatusCode::OK, Json(group_response(group))).into_response()
}

#[tracing::instrument(skip(state, identity, payload), fields(slug = %slug))]
async fn update_group(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    Json(payload): Json<UpdateGroupRequest>,
) -> impl IntoResponse {
    let resource = format!("groups/{slug}");
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "write", &resource) {
        metrics::forbidden_access(&resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = %resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let repo = GroupRepo::new(&state.db);
    let mut group = match repo.get_by_slug(&slug).await {
        Ok(Some(group)) => group,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "group_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let mut updated = false;
    if let Some(slug) = payload.slug.as_deref() {
        let slug = slug.trim();
        if slug.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_slug",
                }),
            )
                .into_response();
        }
        if slug != group.slug {
            match repo.get_by_slug(slug).await {
                Ok(Some(_)) => {
                    return (
                        StatusCode::CONFLICT,
                        Json(ErrorResponse {
                            error: "slug_taken",
                        }),
                    )
                        .into_response();
                }
                Ok(None) => {}
                Err(_) => {
                    tracing::error!(event = "group_update_failed", "DB error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse { error: "db_error" }),
                    )
                        .into_response();
                }
            }
            group.slug = slug.to_string();
            updated = true;
        }
    }
    if let Some(name) = payload.name.as_deref() {
        let name = name.trim();
        if name.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_name",
                }),
            )
                .into_response();
        }
        if name != group.name {
            group.name = name.to_string();
            updated = true;
        }
    }

    if !updated {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_changes",
            }),
        )
            .into_response();
    }

    let Ok(affected) = repo.update(group.id, &group.slug, &group.name).await else {
        tracing::error!(event = "group_update_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };
    if affected == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    tracing::info!(
        event = "group_updated",
        group_id = %group.id,
        "Group updated"
    );
    (StatusCode::OK, Json(group_response(group))).into_response()
}

#[tracing::instrument(skip(state, identity), fields(slug = %slug))]
async fn delete_group(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(slug): axum::extract::Path<String>,
) -> impl IntoResponse {
    let resource = format!("groups/{slug}");
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "write", &resource) {
        metrics::forbidden_access(&resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = %resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let repo = GroupRepo::new(&state.db);
    let group = match repo.get_by_slug(&slug).await {
        Ok(Some(group)) => group,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "group_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let Ok(affected) = repo.delete_by_id(group.id).await else {
        tracing::error!(event = "group_delete_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };
    if affected == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    tracing::info!(
        event = "group_deleted",
        group_id = %group.id,
        "Group deleted"
    );
    StatusCode::NO_CONTENT.into_response()
}

#[tracing::instrument(skip(state, identity, payload), fields(slug = %slug))]
async fn add_member(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(slug): axum::extract::Path<String>,
    Json(payload): Json<AddMemberRequest>,
) -> impl IntoResponse {
    let resource = format!("groups/{slug}/members");
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "write", &resource) {
        metrics::forbidden_access(&resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = %resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let group_repo = GroupRepo::new(&state.db);
    let group = match group_repo.get_by_slug(&slug).await {
        Ok(Some(group)) => group,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "group_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let user_repo = UserRepo::new(&state.db);
    match user_repo.get_by_id(payload.user_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "group_member_add_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let member_repo = GroupMemberRepo::new(&state.db);
    match member_repo.get(group.id, payload.user_id).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "already_member",
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(_) => {
            tracing::error!(event = "group_member_add_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    }

    let member = GroupMember {
        group_id: group.id,
        user_id: payload.user_id,
        created_at: Utc::now(),
    };
    if member_repo.create(&member).await.is_err() {
        tracing::error!(event = "group_member_add_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    }

    tracing::info!(
        event = "group_member_added",
        group_id = %group.id,
        user_id = %payload.user_id,
        "Group member added"
    );
    (StatusCode::CREATED, Json(group_member_response(member))).into_response()
}

#[tracing::instrument(skip(state, identity), fields(slug = %slug, user_id = %user_id))]
async fn remove_member(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((slug, user_id)): axum::extract::Path<(String, Uuid)>,
) -> impl IntoResponse {
    let resource = format!("groups/{slug}/members/{user_id}");
    let policies = state.policy_store.get();
    if !policies.is_allowed(&identity, "write", &resource) {
        metrics::forbidden_access(&resource);
        tracing::warn!(
            event = "forbidden",
            action = "write",
            resource = %resource,
            "Access denied"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    let group_repo = GroupRepo::new(&state.db);
    let group = match group_repo.get_by_slug(&slug).await {
        Ok(Some(group)) => group,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "group_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let member_repo = GroupMemberRepo::new(&state.db);
    let Ok(affected) = member_repo.delete(group.id, user_id).await else {
        tracing::error!(event = "group_member_remove_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };
    if affected == 0 {
        return StatusCode::NOT_FOUND.into_response();
    }

    tracing::info!(
        event = "group_member_removed",
        group_id = %group.id,
        user_id = %user_id,
        "Group member removed"
    );
    StatusCode::NO_CONTENT.into_response()
}

fn group_response(group: Group) -> GroupResponse {
    GroupResponse {
        id: group.id.to_string(),
        slug: group.slug,
        name: group.name,
        created_at: group.created_at.to_rfc3339(),
    }
}

fn group_member_response(member: GroupMember) -> GroupMemberResponse {
    GroupMemberResponse {
        group_id: member.group_id.to_string(),
        user_id: member.user_id.to_string(),
        created_at: member.created_at.to_rfc3339(),
    }
}
