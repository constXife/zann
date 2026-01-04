use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
    Extension, Json, Router,
};
use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zann_core::{Device, Identity};
use zann_db::repo::DeviceRepo;

use crate::app::AppState;
use crate::infra::metrics;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ListDevicesQuery {
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct DeviceResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) fingerprint: String,
    pub(crate) os: Option<String>,
    pub(crate) os_version: Option<String>,
    pub(crate) app_version: Option<String>,
    pub(crate) last_seen_at: Option<String>,
    pub(crate) last_ip: Option<String>,
    pub(crate) revoked_at: Option<String>,
    pub(crate) created_at: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct DeviceListResponse {
    pub(crate) devices: Vec<DeviceResponse>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/current", get(current_device))
        .route("/v1/devices/:id", delete(revoke_device))
}

#[tracing::instrument(skip(state, identity, query))]
async fn list_devices(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Query(query): Query<ListDevicesQuery>,
) -> impl IntoResponse {
    let resource = "devices";
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

    let repo = DeviceRepo::new(&state.db);
    let Ok(devices) = repo
        .list_by_user(identity.user_id, limit, offset, sort)
        .await
    else {
        tracing::error!(event = "devices_list_failed", "DB error");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response();
    };

    let devices: Vec<DeviceResponse> = devices.into_iter().map(device_response).collect();
    tracing::info!(
        event = "devices_listed",
        count = devices.len(),
        "Devices listed"
    );
    (StatusCode::OK, Json(DeviceListResponse { devices })).into_response()
}

#[tracing::instrument(skip(state, identity))]
async fn current_device(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> impl IntoResponse {
    let Some(device_id) = identity.device_id else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let repo = DeviceRepo::new(&state.db);
    let device = match repo.get_by_id(device_id).await {
        Ok(Some(device)) => device,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "device_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    if device.user_id != identity.user_id {
        return StatusCode::NOT_FOUND.into_response();
    }

    (StatusCode::OK, Json(device_response(device))).into_response()
}

#[tracing::instrument(skip(state, identity), fields(device_id = %device_id))]
async fn revoke_device(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(device_id): axum::extract::Path<Uuid>,
) -> impl IntoResponse {
    let resource = format!("devices/{device_id}");
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

    let repo = DeviceRepo::new(&state.db);
    let device = match repo.get_by_id(device_id).await {
        Ok(Some(device)) => device,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => {
            tracing::error!(event = "device_get_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    if device.user_id != identity.user_id {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Ok(affected) = repo.revoke(device_id, Utc::now()).await else {
        tracing::error!(event = "device_revoke_failed", "DB error");
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
        event = "device_revoked",
        device_id = %device_id,
        "Device revoked"
    );
    StatusCode::NO_CONTENT.into_response()
}

fn device_response(device: Device) -> DeviceResponse {
    DeviceResponse {
        id: device.id.to_string(),
        name: device.name,
        fingerprint: device.fingerprint,
        os: device.os,
        os_version: device.os_version,
        app_version: device.app_version,
        last_seen_at: device.last_seen_at.map(|dt| dt.to_rfc3339()),
        last_ip: device.last_ip,
        revoked_at: device.revoked_at.map(|dt| dt.to_rfc3339()),
        created_at: device.created_at.to_rfc3339(),
    }
}
