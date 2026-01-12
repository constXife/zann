use axum::{
    extract::State, http::StatusCode, response::IntoResponse, routing::get, routing::put,
    Extension, Json, Router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zann_core::api::vaults::VaultListResponse;
use zann_core::{CachePolicy, Identity, Vault, VaultEncryptionType, VaultKind};

use crate::app::AppState;
use crate::domains::vaults::service::{
    self, CreateVaultCommand, ListVaultsCommand, UpdateVaultKeyCommand, VaultServiceError,
};

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
        VaultServiceError::NotFound => StatusCode::NOT_FOUND.into_response(),
        VaultServiceError::BadRequest(code) => {
            (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: code })).into_response()
        }
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
    }
}
