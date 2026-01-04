use zann_core::Item;

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

pub(super) fn item_response(item: Item) -> ItemResponse {
    ItemResponse {
        id: item.id.to_string(),
        vault_id: item.vault_id.to_string(),
        path: item.path,
        name: item.name,
        type_id: item.type_id,
        tags: item.tags.map(|tags| tags.0),
        favorite: item.favorite,
        payload_enc: item.payload_enc,
        checksum: item.checksum,
        version: item.version,
        deleted_at: item.deleted_at.map(|dt| dt.to_rfc3339()),
        updated_at: item.updated_at.to_rfc3339(),
    }
}
