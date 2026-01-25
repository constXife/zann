use axum::{
    extract::State, http::StatusCode, response::IntoResponse, routing::get, routing::put,
    Extension, Json, Router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zann_core::api::vaults::{PersonalVaultStatusResponse, VaultListResponse};
use zann_core::{CachePolicy, Identity, Vault, VaultEncryptionType, VaultKind};
use zann_db::repo::VaultRepo;

use crate::app::AppState;
use crate::domains::vaults::service::{
    self, CreateVaultCommand, ListVaultsCommand, UpdateVaultKeyCommand, VaultServiceError,
};
use crate::infra::metrics;

mod vaults_service_account;
use vaults_service_account::list_service_account_vaults;
pub(crate) mod shared;

#[derive(Serialize, JsonSchema)]
pub(crate) struct ErrorResponse {
    error: &'static str,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct ListVaultsQuery {
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct CreateVaultRequest {
    #[serde(default)]
    id: Option<String>,
    slug: String,
    name: String,
    kind: VaultKind,
    cache_policy: CachePolicy,
    #[serde(default)]
    vault_key_enc: Option<Vec<u8>>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct UpdateVaultKeyRequest {
    vault_key_enc: Vec<u8>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct VaultResponse {
    pub(crate) id: String,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) kind: VaultKind,
    pub(crate) cache_policy: CachePolicy,
    pub(crate) vault_key_enc: Vec<u8>,
    pub(crate) encryption_type: VaultEncryptionType,
    pub(crate) tags: Option<Vec<String>>,
    pub(crate) created_at: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/vaults", get(list_vaults).post(create_vault))
        .route("/v1/vaults/personal/status", get(personal_status))
        .route("/v1/vaults/:vault_id", get(get_vault).delete(delete_vault))
        .route("/v1/vaults/:vault_id/key", put(update_vault_key))
        .merge(shared::router())
}

#[tracing::instrument(skip(state, identity, query))]
async fn list_vaults(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Query(query): axum::extract::Query<ListVaultsQuery>,
) -> axum::response::Response {
    if identity.service_account_id.is_some() {
        return list_service_account_vaults(state, identity).await;
    }

    let command = ListVaultsCommand {
        sort: query.sort.clone(),
        limit: query.limit,
        offset: query.offset,
    };
    let vaults = match service::list_vault_summaries(&state, &identity, command).await {
        Ok(vaults) => vaults,
        Err(err) => return map_vault_error(err),
    };

    tracing::info!(event = "vaults_listed", "Vault list returned");
    let body = VaultListResponse { vaults };
    (axum::http::StatusCode::OK, Json(body)).into_response()
}

#[tracing::instrument(skip(state, identity))]
async fn personal_status(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
) -> impl IntoResponse {
    let resource = "vaults/*";
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

    if !state.config.server.personal_vaults_enabled {
        let response = PersonalVaultStatusResponse {
            personal_vaults_present: false,
            personal_key_envelopes_present: false,
            personal_vault_id: None,
        };
        return (StatusCode::OK, Json(response)).into_response();
    }

    let repo = VaultRepo::new(&state.db);
    let vault = match repo.get_personal_by_user(identity.user_id).await {
        Ok(vault) => vault,
        Err(_) => {
            tracing::error!(event = "personal_vault_status_failed", "DB error");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "db_error" }),
            )
                .into_response();
        }
    };

    let personal_vaults_present = vault.is_some();
    let personal_vault_id = vault.as_ref().map(|vault| vault.id);
    let personal_key_envelopes_present = vault
        .as_ref()
        .map(|vault| {
            vault.kind == VaultKind::Personal
                && vault.encryption_type == VaultEncryptionType::Client
                && !vault.vault_key_enc.is_empty()
        })
        .unwrap_or(false);
    if let Some(vault) = vault.as_ref() {
        if vault.kind != VaultKind::Personal
            || vault.encryption_type != VaultEncryptionType::Client
            || vault.vault_key_enc.is_empty()
        {
            tracing::warn!(
                event = "personal_vault_status_mismatch",
                user_id = %identity.user_id,
                email = %identity.email,
                source = ?identity.source,
                vault_id = %vault.id,
                kind = ?vault.kind,
                encryption_type = ?vault.encryption_type,
                vault_key_len = vault.vault_key_enc.len(),
                "Personal vault status mismatch"
            );
        }
    }
    tracing::info!(
        event = "personal_vault_status",
        user_id = %identity.user_id,
        email = %identity.email,
        source = ?identity.source,
        personal_vaults_present,
        personal_key_envelopes_present,
        personal_vault_id = ?personal_vault_id,
        "Personal vault status resolved"
    );

    let response = PersonalVaultStatusResponse {
        personal_vaults_present,
        personal_key_envelopes_present,
        personal_vault_id,
    };
    (StatusCode::OK, Json(response)).into_response()
}

#[tracing::instrument(skip(state, identity, payload))]
async fn create_vault(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    Json(payload): Json<CreateVaultRequest>,
) -> impl IntoResponse {
    let command = CreateVaultCommand {
        id: payload.id,
        slug: payload.slug,
        name: payload.name,
        kind: payload.kind,
        cache_policy: payload.cache_policy,
        vault_key_enc: payload.vault_key_enc,
        tags: payload.tags,
    };
    match service::create_vault(&state, &identity, command).await {
        Ok(vault) => (StatusCode::CREATED, Json(vault_response(vault))).into_response(),
        Err(err) => map_vault_error(err),
    }
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id))]
async fn get_vault(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match service::get_vault(&state, &identity, &vault_id).await {
        Ok(vault) => (StatusCode::OK, Json(vault_response(vault))).into_response(),
        Err(err) => map_vault_error(err),
    }
}

#[tracing::instrument(skip(state, identity, payload), fields(vault_id = %vault_id))]
async fn update_vault_key(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
    Json(payload): Json<UpdateVaultKeyRequest>,
) -> impl IntoResponse {
    let command = UpdateVaultKeyCommand {
        vault_id,
        vault_key_enc: payload.vault_key_enc,
    };
    match service::update_vault_key(&state, &identity, command).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => map_vault_error(err),
    }
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id))]
async fn delete_vault(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match service::delete_vault(&state, &identity, &vault_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => map_vault_error(err),
    }
}

fn vault_response(vault: Vault) -> VaultResponse {
    VaultResponse {
        id: vault.id.to_string(),
        slug: vault.slug,
        name: vault.name,
        kind: vault.kind,
        cache_policy: vault.cache_policy,
        vault_key_enc: vault.vault_key_enc,
        encryption_type: vault.encryption_type,
        tags: vault.tags.map(|tags| tags.0),
        created_at: vault.created_at.to_rfc3339(),
    }
}

fn map_vault_error(error: VaultServiceError) -> axum::response::Response {
    match error {
        VaultServiceError::ForbiddenNoBody => StatusCode::FORBIDDEN.into_response(),
        VaultServiceError::Forbidden(code) => {
            (StatusCode::FORBIDDEN, Json(ErrorResponse { error: code })).into_response()
        }
        VaultServiceError::Unauthorized(code) => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        VaultServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
        VaultServiceError::BadRequest(code) => {
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: code })).into_response()
        }
        VaultServiceError::Conflict(code) => {
            (StatusCode::CONFLICT, Json(ErrorResponse { error: code })).into_response()
        }
        VaultServiceError::PayloadTooLarge(code) => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        VaultServiceError::DbError => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "db_error" }),
        )
            .into_response(),
        VaultServiceError::Internal(code) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: code }),
        )
            .into_response(),
        VaultServiceError::NoChanges => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no_changes",
            }),
        )
            .into_response(),
        VaultServiceError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_password",
            }),
        )
            .into_response(),
        VaultServiceError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_credentials",
            }),
        )
            .into_response(),
        VaultServiceError::Kdf => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: "kdf_error" }),
        )
            .into_response(),
        VaultServiceError::DeviceRequired => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "device_required",
            }),
        )
            .into_response(),
        VaultServiceError::PolicyMismatch { .. } => (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "policy_mismatch",
            }),
        )
            .into_response(),
    }
}
