use axum::http::HeaderMap;
use axum::{
    body::Bytes,
    extract::{Query, State},
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;
use zann_core::Identity;

use crate::app::AppState;
use crate::domains::items::service::{self, FileRepresentation};

use super::items_models::FileUploadResponse;
use super::map_items_error;

#[derive(Debug, Deserialize)]
pub(super) struct FileUploadQuery {
    pub(super) representation: Option<String>,
    pub(super) file_id: Option<String>,
    pub(super) filename: Option<String>,
    pub(super) mime: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FileDownloadQuery {
    pub(super) representation: Option<String>,
}

#[tracing::instrument(skip(state, identity, body), fields(vault_id = %vault_id, item_id = %item_id))]
pub(super) async fn upload_item_file(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id)): axum::extract::Path<(String, Uuid)>,
    Query(query): Query<FileUploadQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let Some(representation) = query.representation.as_deref() else {
        return map_items_error(service::ItemsError::BadRequest("representation_required"));
    };
    let representation = match FileRepresentation::parse(representation) {
        Ok(value) => value,
        Err(code) => return map_items_error(service::ItemsError::BadRequest(code)),
    };
    let Some(file_id) = query.file_id.as_deref() else {
        return map_items_error(service::ItemsError::BadRequest("file_id_required"));
    };
    let file_id = match Uuid::parse_str(file_id) {
        Ok(value) => value,
        Err(_) => return map_items_error(service::ItemsError::BadRequest("file_id_invalid")),
    };
    let filename = query.filename.filter(|value| !value.trim().is_empty());
    let mime = query
        .mime
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.to_string())
        });

    let result = match service::upload_item_file(
        &state,
        &identity,
        &vault_id,
        item_id,
        representation,
        file_id,
        body.to_vec(),
        filename,
        mime,
    )
    .await
    {
        Ok(result) => result,
        Err(error) => return map_items_error(error),
    };

    Json(FileUploadResponse {
        file_id: result.file_id.to_string(),
        upload_state: "ready".to_string(),
    })
    .into_response()
}

#[tracing::instrument(skip(state, identity), fields(vault_id = %vault_id, item_id = %item_id))]
pub(super) async fn download_item_file(
    State(state): State<AppState>,
    Extension(identity): Extension<Identity>,
    axum::extract::Path((vault_id, item_id)): axum::extract::Path<(String, Uuid)>,
    Query(query): Query<FileDownloadQuery>,
) -> impl IntoResponse {
    let Some(representation) = query.representation.as_deref() else {
        return map_items_error(service::ItemsError::BadRequest("representation_required"));
    };
    let representation = match FileRepresentation::parse(representation) {
        Ok(value) => value,
        Err(code) => return map_items_error(service::ItemsError::BadRequest(code)),
    };

    let result =
        match service::download_item_file(&state, &identity, &vault_id, item_id, representation)
            .await
        {
            Ok(result) => result,
            Err(error) => return map_items_error(error),
        };

    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        result.bytes,
    )
        .into_response()
}
