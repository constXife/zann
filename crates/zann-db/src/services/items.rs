use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use zann_core::{
    ChangeType, EncryptedPayload, ItemDetail, ItemListParams, ItemPreviewPage, ItemsService,
    ServiceError, ServiceResult, SyncStatus,
};

use crate::local::{LocalItemRepo, LocalPendingChange, PendingChangeRepo};

use super::LocalServices;

#[async_trait]
impl<'a> ItemsService for LocalServices<'a> {
    async fn list_items(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        params: ItemListParams,
    ) -> ServiceResult<ItemPreviewPage> {
        self.list_page(storage_id, vault_id, params).await
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
        self.decrypt_payload(storage_id, item.vault_id, item.id, &item.payload_enc)
            .await?;
        let expected = item.clone();
        let pending_repo = PendingChangeRepo::new(self.pool);
        let pending = pending_repo
            .list_by_item(storage_id, item_id)
            .await
            .map_err(|err| ServiceError::new("pending_change_failed", err.to_string()))?;
        let has_pending_create = pending
            .iter()
            .any(|change| change.operation == ChangeType::Create && change.base_seq.is_none());
        if has_pending_create {
            item.deleted_at = Some(Utc::now());
            item.sync_status = SyncStatus::LocalDeleted;
            item.updated_at = Utc::now();
            item.version = item.version.saturating_add(1);
            self.commit_item_edit(&expected, &item, None, None).await?;
            return Ok(());
        }
        let prev_version = item.version;
        item.deleted_at = Some(Utc::now());
        item.sync_status = SyncStatus::Tombstone;
        item.updated_at = Utc::now();
        item.version = item.version.saturating_add(1);
        self.commit_item_edit(
            &expected,
            &item,
            None,
            Some(&LocalPendingChange {
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
            }),
        )
        .await?;
        Ok(())
    }
}
