use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use zann_core::{
    EncryptedPayload, ItemDetail, ItemListParams, ItemPreview, ItemPreviewPage, ItemsService,
    ServiceError, ServiceResult,
};

use crate::local::{LocalItem, LocalItemRepo, LocalPendingChange, PendingChangeRepo};

use super::LocalServices;

#[async_trait]
impl<'a> ItemsService for LocalServices<'a> {
    async fn list_items(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        params: ItemListParams,
    ) -> ServiceResult<ItemPreviewPage> {
        let repo = LocalItemRepo::new(self.pool);
        let items = repo
            .list_by_vault(storage_id, vault_id, params.include_deleted)
            .await
            .map_err(|err| ServiceError::new("item_list_failed", err.to_string()))?;
        Ok(ItemPreviewPage {
            items: items
                .into_iter()
                .map(|item| ItemPreview {
                    id: item.id,
                    vault_id: item.vault_id,
                    path: item.path,
                    name: item.name,
                    type_id: item.type_id,
                    sync_status: item.sync_status,
                    updated_at: item.updated_at,
                    deleted_at: item.deleted_at,
                })
                .collect(),
            next_cursor: None,
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
            "[item_debug] get_item_by_path item_id={} vault_id={} checksum={} cache_key_fp={} updated_at={} sync_status={} payload_len={}",
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
            "[item_debug] get_item item_id={} vault_id={} checksum={} cache_key_fp={} updated_at={} sync_status={} payload_len={}",
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
        let repo = LocalItemRepo::new(self.pool);
        let existing = repo
            .get_by_vault_path(storage_id, vault_id, &path)
            .await
            .map_err(|err| ServiceError::new("item_lookup_failed", err.to_string()))?;
        let now = Utc::now();
        if let Some(mut item) = existing {
            let prev_version = item.version;
            let (payload_enc, key_fp) = self
                .encrypt_payload(storage_id, vault_id, item.id, &payload)
                .await?;
            item.payload_enc = payload_enc;
            item.checksum = Self::payload_checksum(&item.payload_enc);
            item.cache_key_fp = Some(key_fp);
            item.version = item.version.saturating_add(1);
            item.updated_at = now;
            item.name = Self::name_from_path(&path);
            item.type_id = type_id;
            item.sync_status = "modified".to_string();
            repo.update(&item)
                .await
                .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
            self.track_pending(
                storage_id,
                LocalPendingChange {
                    id: Uuid::now_v7(),
                    storage_id,
                    vault_id,
                    item_id: item.id,
                    operation: "update".to_string(),
                    payload_enc: Some(item.payload_enc.clone()),
                    checksum: Some(item.checksum.clone()),
                    path: Some(item.path.clone()),
                    name: Some(item.name.clone()),
                    type_id: Some(item.type_id.clone()),
                    base_seq: Some(prev_version),
                    created_at: now,
                },
            )
            .await?;
            return Ok(item.id);
        }

        let item_id = Uuid::now_v7();
        let (payload_enc, key_fp) = self
            .encrypt_payload(storage_id, vault_id, item_id, &payload)
            .await?;
        let checksum = Self::payload_checksum(&payload_enc);
        let item = LocalItem {
            id: item_id,
            storage_id,
            vault_id,
            path: path.clone(),
            name: Self::name_from_path(&path),
            type_id,
            payload_enc,
            checksum,
            cache_key_fp: Some(key_fp),
            version: 1,
            deleted_at: None,
            updated_at: now,
            sync_status: "modified".to_string(),
        };
        repo.create(&item)
            .await
            .map_err(|err| ServiceError::new("item_create_failed", err.to_string()))?;
        self.track_pending(
            storage_id,
            LocalPendingChange {
                id: Uuid::now_v7(),
                storage_id,
                vault_id,
                item_id,
                operation: "create".to_string(),
                payload_enc: Some(item.payload_enc.clone()),
                checksum: Some(item.checksum.clone()),
                path: Some(item.path.clone()),
                name: Some(item.name.clone()),
                type_id: Some(item.type_id.clone()),
                base_seq: None,
                created_at: now,
            },
        )
        .await?;
        Ok(item_id)
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
            .any(|change| change.operation == "create" && change.base_seq.is_none());
        if has_pending_create {
            let _ = pending_repo.delete_by_item(storage_id, item_id).await;
            item.deleted_at = Some(Utc::now());
            item.sync_status = "local_deleted".to_string();
            item.updated_at = Utc::now();
            item.version = item.version.saturating_add(1);
            repo.update(&item)
                .await
                .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
            return Ok(());
        }
        let prev_version = item.version;
        item.deleted_at = Some(Utc::now());
        item.sync_status = "tombstone".to_string();
        item.updated_at = Utc::now();
        item.version = item.version.saturating_add(1);
        repo.update(&item)
            .await
            .map_err(|err| ServiceError::new("item_update_failed", err.to_string()))?;
        self.track_pending(
            storage_id,
            LocalPendingChange {
                id: Uuid::now_v7(),
                storage_id,
                vault_id: item.vault_id,
                item_id: item.id,
                operation: "delete".to_string(),
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
