macro_rules! db_query {
    ($sql:expr $(, $arg:expr)* $(,)?) => {
        sqlx_core::query::query($sql)$(.bind($arg))*
    };
}
// Atomic item + history + pending publication, used by local editing and backup restoration.
use super::*;
use crate::local::LocalItem;

impl LocalServices<'_> {
    pub fn validate_item_input(
        path: &str,
        type_id: &str,
        payload: &EncryptedPayload,
        metadata: &zann_core::ItemMetadata,
    ) -> ServiceResult<String> {
        if !metadata.validate() {
            return Err(ServiceError::new(
                "invalid_item_metadata",
                "invalid item metadata",
            ));
        }
        let canonical_path = Self::normalize_path(path)?;
        Self::validate_payload_size(payload)?;
        if type_id.is_empty()
            || type_id.len() > 128
            || type_id.trim() != type_id
            || payload.type_id != type_id
        {
            return Err(ServiceError::new("item_type_mismatch", "invalid item type"));
        }
        Ok(canonical_path)
    }

    pub async fn put_item_with_metadata(
        &self,
        storage_id: Uuid,
        vault_id: Uuid,
        path: String,
        type_id: String,
        payload: EncryptedPayload,
        metadata: zann_core::ItemMetadata,
    ) -> Result<Uuid, Box<dyn std::error::Error + Send + Sync>> {
        Self::validate_item_input(&path, &type_id, &payload, &metadata)?;
        let mut batch = self.begin_item_batch(storage_id, vault_id).await?;
        let id = batch.add(path, type_id, payload, metadata).await?;
        batch.commit().await?;
        Ok(id)
    }
}

pub(super) async fn insert_created_item(
    tx: &mut sqlx_core::transaction::Transaction<'_, sqlx_sqlite::Sqlite>,
    item: &LocalItem,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    db_query!(
            "INSERT INTO items_cache (id,storage_id,vault_id,path,name,type_id,payload_enc,checksum,cache_key_fp,version,updated_at,sync_status,metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,1,?10,?11,?12)",
            item.id, item.storage_id, item.vault_id, &item.path, &item.name, &item.type_id, &item.payload_enc,
            &item.checksum, &item.cache_key_fp, item.updated_at, item.sync_status.as_i32(), item.metadata.as_ref().map(sqlx_core::types::Json)
        ).execute(&mut **tx).await?;
    db_query!(
            "INSERT INTO item_history (id,storage_id,vault_id,item_id,payload_enc,checksum,version,change_type,changed_by_email,source,sync_status,created_at) VALUES (?1,?2,?3,?4,?5,?6,1,?7,'local',?8,?9,?10)",
            Uuid::now_v7(), item.storage_id, item.vault_id, item.id, &item.payload_enc, &item.checksum,
            ChangeType::Create.as_i32(), HistorySource::Local.as_i32(), HistorySyncStatus::Pending.as_i32(), item.updated_at
        ).execute(&mut **tx).await?;
    db_query!(
            "INSERT INTO pending_changes (id,storage_id,vault_id,item_id,operation,payload_enc,checksum,path,name,type_id,created_at,metadata) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            Uuid::now_v7(), item.storage_id, item.vault_id, item.id, ChangeType::Create.as_i32(), &item.payload_enc,
            &item.checksum, &item.path, &item.name, &item.type_id, item.updated_at, item.metadata.as_ref().map(sqlx_core::types::Json)
        ).execute(&mut **tx).await?;
    Ok(())
}
