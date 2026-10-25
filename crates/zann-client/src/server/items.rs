use reqwest::Method;
use serde_json::Value;
use uuid::Uuid;

use super::{ServerClient, ServerError};
pub use zann_core::api::items::*;
pub use zann_core::api::vaults::VaultListResponse;

fn identifier(value: &str) -> Result<&str, ServerError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ServerError::input("invalid resource identifier"));
    }
    Ok(value)
}
impl ServerClient {
    async fn read<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        bearer: &str,
        path: &str,
        query: &[(String, String)],
    ) -> Result<T, ServerError> {
        self.check_endpoint(endpoint)?;
        Ok(self
            .transport
            .server_json(Method::GET, path, bearer, None, query)
            .await?)
    }
    async fn write<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        bearer: &str,
        method: Method,
        path: &str,
        payload: &Value,
    ) -> Result<T, ServerError> {
        self.check_endpoint(endpoint)?;
        if payload.to_string().len() > 2 * 1024 * 1024 {
            return Err(ServerError::input("payload exceeds limit"));
        }
        Ok(self
            .transport
            .server_json(method, path, bearer, Some(payload), &[])
            .await?)
    }
}
pub async fn fetch_vaults(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
) -> Result<VaultListResponse, ServerError> {
    client.read(endpoint, bearer, "v1/vaults", &[]).await
}
pub async fn fetch_shared_item(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
    vault: &str,
    id: Uuid,
) -> Result<SharedItemResponse, ServerError> {
    client
        .read(
            endpoint,
            bearer,
            &format!("v1/vaults/{}/items/{id}", identifier(vault)?),
            &[],
        )
        .await
}
pub(super) async fn fetch_item_summaries(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
    vault: &str,
    prefix: Option<&str>,
) -> Result<Vec<ItemSummaryResponse>, ServerError> {
    let query = prefix
        .map(|value| vec![("prefix".into(), value.to_string())])
        .unwrap_or_default();
    let response: ItemsResponse = client
        .read(
            endpoint,
            bearer,
            &format!("v1/vaults/{}/items", identifier(vault)?),
            &query,
        )
        .await?;
    if response.items.len() > 500 {
        return Err(ServerError::input("item page exceeds limit"));
    }
    Ok(response.items)
}
pub async fn create_shared_item(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
    vault: &str,
    path: &str,
    type_id: &str,
    payload: Value,
) -> Result<SharedItemResponse, ServerError> {
    let body =
        serde_json::json!({"vault_id":vault,"path":path,"type_id":type_id,"payload":payload});
    client
        .write(endpoint, bearer, Method::POST, "v1/shared/items", &body)
        .await
}
pub async fn update_shared_item(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
    id: &str,
    payload: Option<Value>,
    new_path: Option<&str>,
) -> Result<SharedItemResponse, ServerError> {
    let mut body = serde_json::Map::new();
    if let Some(payload) = payload {
        body.insert("payload".into(), payload);
    }
    if let Some(path) = new_path {
        body.insert("path".into(), path.into());
    }
    client
        .write(
            endpoint,
            bearer,
            Method::PUT,
            &format!("v1/shared/items/{}", identifier(id)?),
            &body.into(),
        )
        .await
}
pub async fn delete_shared_item(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
    id: &str,
) -> Result<(), ServerError> {
    client.check_endpoint(endpoint)?;
    Ok(client
        .transport
        .server_delete(&format!("v1/shared/items/{}", identifier(id)?), bearer)
        .await?)
}
pub async fn set_secret_value(
    client: &ServerClient,
    endpoint: &str,
    bearer: &str,
    vault: &str,
    path: &str,
    value: &str,
) -> Result<zann_core::api::secrets::SecretResponse, ServerError> {
    client.check_endpoint(endpoint)?;
    let secrets = crate::secrets::SecretsClient::new(
        endpoint,
        bearer,
        crate::secrets::SecretsTransportSecurity::AllowLoopbackHttp,
    )?;
    secrets
        .set(
            vault,
            path,
            &crate::secrets::SecretSetRequest {
                value: value.to_string(),
                policy: None,
                meta: None,
            },
        )
        .await
        .map_err(Into::into)
}
