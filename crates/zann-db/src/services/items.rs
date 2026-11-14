use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use zann_core::{
    item_subtitle, ChangeType, EncryptedPayload, ItemCounts, ItemDetail, ItemListParams,
    ItemPreview, ItemPreviewPage, ItemsService, ServiceError, ServiceResult, SyncStatus,
};

use crate::local::{LocalItem, LocalItemRepo, LocalPendingChange, PendingChangeRepo};

use super::LocalServices;

fn build_fts_query(input: &str) -> Option<String> {
    let mut tokens = Vec::new();
    for token in input.split_whitespace() {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let escaped = trimmed.replace('"', "\"\"");
        tokens.push(format!("\"{}\"*", escaped));
    }
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

fn encode_cursor(item: &LocalItem) -> String {
    format!("{}|{}", item.updated_at.to_rfc3339(), item.id)
}

fn parse_cursor(cursor: &str) -> Option<(DateTime<Utc>, Uuid)> {
    let (ts, id) = cursor.split_once('|')?;
    let ts = DateTime::parse_from_rfc3339(ts).ok()?.with_timezone(&Utc);
    let id = Uuid::parse_str(id).ok()?;
    Some((ts, id))
}

#[async_trait]
impl<'a> ItemsService for LocalServices<'a> {
    async fn list_items(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        params: ItemListParams,
    ) -> ServiceResult<ItemPreviewPage> {
        let limit = params.limit.unwrap_or(200).clamp(1, 1000) as i64;
        let search_query = params
            .query
            .as_deref()
            .and_then(|query| build_fts_query(query.trim()));
        let cursor = match params.cursor.as_deref() {
            Some(cursor) => Some(
                parse_cursor(cursor)
                    .ok_or_else(|| ServiceError::new("invalid_cursor", "invalid cursor"))?,
            ),
            None => None,
        };
        let repo = LocalItemRepo::new(self.pool);
        let total_count = match search_query.as_deref() {
            Some(query) => repo
                .count_by_vault_with_query(storage_id, vault_id, params.include_deleted, query)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
            None => repo
                .count_by_vault_all(storage_id, vault_id, params.include_deleted)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
        };
        let active_count = match search_query.as_deref() {
            Some(query) => repo
                .count_by_vault_with_query(storage_id, vault_id, false, query)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
            None => repo
                .count_by_vault(storage_id, vault_id)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
        };
        let trash_count = match search_query.as_deref() {
            Some(query) => repo
                .count_deleted_by_vault_with_query(storage_id, vault_id, query)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
            None => repo
                .count_deleted_by_vault(storage_id, vault_id)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
        };
        let type_counts = match search_query.as_deref() {
            Some(query) => repo
                .count_by_vault_grouped_with_query(storage_id, vault_id, query)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
            None => repo
                .count_by_vault_grouped(storage_id, vault_id)
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
        };
        let mut by_type = std::collections::HashMap::new();
        for (type_id, count) in type_counts {
            by_type.insert(type_id, count as usize);
        }
        let mut items = match search_query.as_deref() {
            Some(query) => repo
                .list_by_vault_paged_with_query(
                    storage_id,
                    vault_id,
                    params.include_deleted,
                    query,
                    limit + 1,
                    cursor,
                )
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
            None => repo
                .list_by_vault_paged(
                    storage_id,
                    vault_id,
                    params.include_deleted,
                    limit + 1,
                    cursor,
                )
                .await
                .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?,
        };
        let next_cursor = if items.len() > limit as usize {
            items.pop();
            // The cursor is exclusive (`< updated_at, id`), so it must point
            // at the last item we actually return. Pointing at the lookahead
            // row would skip that row on the next page.
            items.last().map(encode_cursor)
        } else {
            None
        };
        // Subtitles decrypt only the page returned, with the vault key
        // unwrapped once; a vault whose key does not open fails the list, as
        // it fails every item. A single payload that does not open leaves its
        // row without a subtitle, and opening the item reports the error, so
        // one damaged item never hides the rest.
        let keys = self.vault_payload_keys(storage_id, vault_id).await?;
        Ok(ItemPreviewPage {
            items: items
                .into_iter()
                .map(|item| {
                    let subtitle = self
                        .open_payload(&keys, item.id, &item.payload_enc)
                        .ok()
                        .and_then(|payload| item_subtitle(&item.type_id, &payload));
                    ItemPreview {
                        id: item.id,
                        vault_id: item.vault_id,
                        path: item.path,
                        name: item.name,
                        type_id: item.type_id,
                        subtitle,
                        sync_status: item.sync_status,
                        updated_at: item.updated_at,
                        deleted_at: item.deleted_at,
                    }
                })
                .collect(),
            next_cursor,
            total_count: total_count as usize,
            counts: ItemCounts {
                all: active_count as usize,
                trash: trash_count as usize,
                by_type,
            },
        })
    }

    async fn get_item_by_path(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: &str,
    ) -> ServiceResult<Option<ItemDetail>> {
        let repo = LocalItemRepo::new(self.pool);
        let item = repo
            .get_by_vault_path(storage_id, vault_id, path)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?;
        let Some(item) = item else {
            return Ok(None);
        };
        Self::item_debug(format_args!(
            "[item_debug] get_item_by_path item_id={} vault_id={} checksum={} cache_key_fp={} updated_at={} sync_status={:?} payload_len={}",
            item.id,
            item.vault_id,
            item.checksum,
            item.cache_key_fp.as_deref().unwrap_or("-"),
            item.updated_at.to_rfc3339(),
            item.sync_status,
            item.payload_enc.len()
        ));
        let payload = self
            .decrypt_payload(storage_id, item.vault_id, item.id, &item.payload_enc)
            .await?;
        Ok(Some(ItemDetail {
            id: item.id,
            vault_id: item.vault_id,
            path: item.path,
            name: item.name,
            type_id: item.type_id,
            payload,
            updated_at: item.updated_at,
            version: item.version,
        }))
    }

    async fn get_item(&self, storage_id: Uuid, item_id: Uuid) -> ServiceResult<ItemDetail> {
        let repo = LocalItemRepo::new(self.pool);
        let item = repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
            .ok_or_else(|| ServiceError::new("item_not_found", "item not found"))?;
        Self::item_debug(format_args!(
            "[item_debug] get_item item_id={} vault_id={} checksum={} cache_key_fp={} updated_at={} sync_status={:?} payload_len={}",
            item.id,
            item.vault_id,
            item.checksum,
            item.cache_key_fp.as_deref().unwrap_or("-"),
            item.updated_at.to_rfc3339(),
            item.sync_status,
            item.payload_enc.len()
        ));
        let payload = self
            .decrypt_payload(storage_id, item.vault_id, item.id, &item.payload_enc)
            .await?;
        Ok(ItemDetail {
            id: item.id,
            vault_id: item.vault_id,
            path: item.path,
            name: item.name,
            type_id: item.type_id,
            payload,
            updated_at: item.updated_at,
            version: item.version,
        })
    }

    async fn put_item(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: String,
        type_id: String,
        payload: EncryptedPayload,
    ) -> ServiceResult<Uuid> {
        self.put_item_with_metadata(
            storage_id,
            vault_id,
            path,
            type_id,
            payload,
            Default::default(),
        )
        .await
        .map_err(|error| match error.downcast::<ServiceError>() {
            Ok(error) => *error,
            Err(error) => ServiceError::new("item_create_failed", error.to_string()),
        })
    }

    async fn delete_item(&self, storage_id: Uuid, item_id: Uuid) -> ServiceResult<()> {
        let repo = LocalItemRepo::new(self.pool);
        let Some(mut item) = repo
            .get_by_id(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?
        else {
            return Err(ServiceError::new("item_not_found", "item not found"));
        };
        let pending_repo = PendingChangeRepo::new(self.pool);
        let pending = pending_repo
            .list_by_item(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("pending_change_failed", err.to_string()))?;
        let has_pending_create = pending
            .iter()
            .any(|change| change.operation == ChangeType::Create && change.base_seq.is_none());
        if has_pending_create {
            let _ = pending_repo.delete_by_item(storage_id, item_id).await;
            item.deleted_at = Some(Utc::now());
            item.sync_status = SyncStatus::LocalDeleted;
            item.updated_at = Utc::now();
            item.version = item.version.saturating_add(1);
            repo.update(&item)
                .await
                .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
            return Ok(());
        }
        let prev_version = item.version;
        item.deleted_at = Some(Utc::now());
        item.sync_status = SyncStatus::Tombstone;
        item.updated_at = Utc::now();
        item.version = item.version.saturating_add(1);
        repo.update(&item)
            .await
            .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
        self.track_pending(
            storage_id,
            LocalPendingChange {
                metadata: item.metadata.clone(),
                id: Uuid::now_v7(),
                storage_id,
                vault_id: item.vault_id,
                item_id: item.id,
                operation: ChangeType::Delete,
                payload_enc: None,
                checksum: None,
                path: Some(item.path.clone()),
                name: Some(item.name.clone()),
                type_id: Some(item.type_id.clone()),
                base_seq: Some(prev_version),
                created_at: item.updated_at,
            },
        )
        .await?;
        Ok(())
    }
}
