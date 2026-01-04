use super::http::{create_item, delete_item, get_item, list_items, update_item};
use crate::cli_args::*;
use crate::modules::items::{CreateItemRequest, UpdateItemRequest};
use crate::modules::system::http::{parse_base64, print_empty_response, print_json_response};
use crate::modules::system::CommandContext;
use serde::Deserialize;
use uuid::Uuid;
use zann_core::vault_crypto as core_crypto;

pub(crate) async fn handle_item(
    args: ItemArgs,
    ctx: &mut CommandContext<'_>,
) -> anyhow::Result<()> {
    match args.command {
        ItemCommand::List(args) => {
            let response = list_items(ctx, &args.vault_id).await?;
            print_json_response(response).await?;
        }
        ItemCommand::Create(args) => {
            let payload = build_create_payload(
                args.path,
                args.name,
                args.type_id,
                args.tags,
                args.favorite,
                args.payload_base64,
                args.version,
            )?;
            let response = create_item(ctx, &args.vault_id, payload).await?;
            print_json_response(response).await?;
        }
        ItemCommand::Ensure(args) => {
            let response = list_items(ctx, &args.vault_id).await?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!("Request failed: {status} {body}");
            }
            let body: ItemsListResponse = response.json().await?;
            if let Some(item) = body
                .items
                .iter()
                .find(|item| item.path == args.path.as_str())
            {
                let item_id = Uuid::parse_str(&item.id)?;
                let response = get_item(ctx, &args.vault_id, &item_id).await?;
                print_json_response(response).await?;
                return Ok(());
            }
            let payload = build_create_payload(
                args.path,
                args.name,
                args.type_id,
                args.tags,
                args.favorite,
                args.payload_base64,
                args.version,
            )?;
            let response = create_item(ctx, &args.vault_id, payload).await?;
            print_json_response(response).await?;
        }
        ItemCommand::Get(args) => {
            let response = get_item(ctx, &args.vault_id, &args.item_id).await?;
            print_json_response(response).await?;
        }
        ItemCommand::Update(args) => {
            let payload_enc = match args.payload_base64 {
                Some(value) => Some(parse_base64(&value)?),
                None => None,
            };
            let checksum = payload_enc
                .as_ref()
                .map(|bytes| core_crypto::payload_checksum(bytes));
            let tags = if args.tags.is_empty() {
                None
            } else {
                Some(args.tags)
            };
            let payload = UpdateItemRequest {
                path: args.path,
                name: args.name,
                type_id: args.type_id,
                tags,
                favorite: args.favorite,
                payload_enc,
                checksum,
                version: args.version,
                base_version: args.base_version,
            };
            let response = update_item(ctx, &args.vault_id, &args.item_id, payload).await?;
            print_json_response(response).await?;
        }
        ItemCommand::Delete(args) => {
            let response = delete_item(ctx, &args.vault_id, &args.item_id).await?;
            print_empty_response(response, "Item deleted").await?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct ItemsListResponse {
    items: Vec<ItemSummary>,
}

#[derive(Deserialize)]
struct ItemSummary {
    id: String,
    path: String,
}

fn build_create_payload(
    path: String,
    name: String,
    type_id: String,
    tags: Vec<String>,
    favorite: bool,
    payload_base64: String,
    version: Option<i64>,
) -> anyhow::Result<CreateItemRequest> {
    let payload_enc = parse_base64(&payload_base64)?;
    let tags = if tags.is_empty() { None } else { Some(tags) };
    let checksum = core_crypto::payload_checksum(&payload_enc);
    Ok(CreateItemRequest {
        path,
        name,
        type_id,
        tags,
        favorite: Some(favorite),
        payload_enc,
        checksum,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use mockito::Server;
    use serde_json::json;

    fn build_context<'a>(
        client: &'a reqwest::Client,
        addr: &'a str,
        config: &'a mut crate::modules::system::CliConfig,
    ) -> crate::modules::system::CommandContext<'a> {
        crate::modules::system::CommandContext {
            client,
            addr,
            allow_insecure: true,
            access_token: "token".to_string(),
            context_name: None,
            token_name: None,
            config,
        }
    }

    #[tokio::test]
    async fn ensure_returns_existing_item() {
        let mut server = Server::new_async().await;
        let vault_id = "vault-1";
        let path = "apps/service";
        let item_id = Uuid::from_u128(1);
        let list_body = json!({
            "items": [{
                "id": item_id.to_string(),
                "path": path,
            }]
        });
        let item_body = json!({
            "id": item_id.to_string(),
            "vault_id": vault_id,
            "path": path,
            "name": "svc",
            "type_id": "kv",
            "tags": null,
            "favorite": false,
            "payload_enc": [],
            "checksum": "abc",
            "version": 1,
            "deleted_at": null,
            "updated_at": "2024-01-01T00:00:00Z"
        });

        let list_path = format!("/v1/vaults/{vault_id}/items");
        let get_path = format!("/v1/vaults/{vault_id}/items/{item_id}");
        let list_mock = server
            .mock("GET", list_path.as_str())
            .match_header("authorization", "Bearer token")
            .with_status(200)
            .with_body(list_body.to_string())
            .create_async()
            .await;
        let get_mock = server
            .mock("GET", get_path.as_str())
            .match_header("authorization", "Bearer token")
            .with_status(200)
            .with_body(item_body.to_string())
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let mut config = crate::modules::system::CliConfig::default();
        let addr = server.url();
        let mut ctx = build_context(&client, &addr, &mut config);
        let args = ItemArgs {
            command: ItemCommand::Ensure(ItemEnsureArgs {
                vault_id: vault_id.to_string(),
                path: path.to_string(),
                name: "svc".to_string(),
                type_id: "kv".to_string(),
                tags: Vec::new(),
                favorite: false,
                payload_base64: STANDARD.encode("secret"),
                version: None,
            }),
        };

        handle_item(args, &mut ctx).await.expect("ensure ok");
        list_mock.assert_async().await;
        get_mock.assert_async().await;
    }

    #[tokio::test]
    async fn ensure_creates_missing_item() {
        let mut server = Server::new_async().await;
        let vault_id = "vault-2";
        let path = "apps/worker";
        let item_id = Uuid::from_u128(2);
        let list_body = json!({
            "items": []
        });
        let create_body = json!({
            "id": item_id.to_string(),
            "vault_id": vault_id,
            "path": path,
            "name": "worker",
            "type_id": "kv",
            "tags": null,
            "favorite": false,
            "payload_enc": [],
            "checksum": "abc",
            "version": 1,
            "deleted_at": null,
            "updated_at": "2024-01-01T00:00:00Z"
        });

        let list_path = format!("/v1/vaults/{vault_id}/items");
        let create_path = format!("/v1/vaults/{vault_id}/items");
        let list_mock = server
            .mock("GET", list_path.as_str())
            .match_header("authorization", "Bearer token")
            .with_status(200)
            .with_body(list_body.to_string())
            .create_async()
            .await;
        let create_mock = server
            .mock("POST", create_path.as_str())
            .match_header("authorization", "Bearer token")
            .with_status(200)
            .with_body(create_body.to_string())
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let mut config = crate::modules::system::CliConfig::default();
        let addr = server.url();
        let mut ctx = build_context(&client, &addr, &mut config);
        let args = ItemArgs {
            command: ItemCommand::Ensure(ItemEnsureArgs {
                vault_id: vault_id.to_string(),
                path: path.to_string(),
                name: "worker".to_string(),
                type_id: "kv".to_string(),
                tags: Vec::new(),
                favorite: true,
                payload_base64: STANDARD.encode("secret"),
                version: None,
            }),
        };

        handle_item(args, &mut ctx).await.expect("ensure ok");
        list_mock.assert_async().await;
        create_mock.assert_async().await;
    }
}
