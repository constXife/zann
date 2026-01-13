use zann_core::{Item, Vault, VaultEncryptionType};

use crate::app::AppState;
use crate::domains::items::service::{self, ItemsError};

use super::items_models::{ItemResponse, ItemSummary};

pub(super) fn item_summary(item: Item) -> ItemSummary {
    ItemSummary {
        id: item.id.to_string(),
        path: item.path,
        name: item.name,
        type_id: item.type_id,
        tags: item.tags.map(|tags| tags.0),
        favorite: item.favorite,
        checksum: item.checksum,
        version: item.version,
        deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
        updated_at: item.updated_at.to_rfc3339(),
    }
}

pub(super) fn item_response(
    state: &AppState,
    vault: &Vault,
    item: Item,
) -> Result<ItemResponse, ItemsError> {
    let (payload_enc, payload) = if vault.encryption_type == VaultEncryptionType::Server {
        let payload = service::decrypt_payload_json(state, vault, item.id, &item.payload_enc)?;
        (None, Some(payload))
    } else {
        (Some(item.payload_enc), None)
    };
    Ok(ItemResponse {
        id: item.id.to_string(),
        vault_id: item.vault_id.to_string(),
        path: item.path,
        name: item.name,
        type_id: item.type_id,
        tags: item.tags.map(|tags| tags.0),
        favorite: item.favorite,
        payload_enc,
        payload,
        checksum: item.checksum,
        version: item.version,
        deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
        updated_at: item.updated_at.to_rfc3339(),
    })
}
