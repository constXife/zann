//! One local edit: exact-source CAS, history and pending intent commit together.
use super::LocalItemRepo;
use crate::local::{
    LocalItem, LocalItemHistory, LocalItemHistoryRepo, LocalPendingChange, PendingChangeRepo,
};
use zann_core::ChangeType;

impl LocalItemRepo<'_> {
    /// `expected` is the exact snapshot whose plaintext/version the service
    /// admitted. A competing sync invalidates it before any side effect.
    pub async fn commit_edit(
        &self,
        expected: &LocalItem,
        next: &LocalItem,
        history: Option<&LocalItemHistory>,
        pending: Option<&LocalPendingChange>,
    ) -> Result<bool, sqlx_core::Error> {
        if expected.storage_id != next.storage_id
            || expected.id != next.id
            || expected.vault_id != next.vault_id
            || history.is_some_and(|row| {
                row.storage_id != next.storage_id
                    || row.item_id != next.id
                    || row.vault_id != next.vault_id
            })
            || pending.is_some_and(|row| {
                row.storage_id != next.storage_id
                    || row.item_id != next.id
                    || row.vault_id != next.vault_id
            })
        {
            return Err(sqlx_core::Error::Protocol(
                "invalid local item edit scope".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        let affected = query!(
            "UPDATE items_cache SET path=?3,name=?4,type_id=?5,payload_enc=?6,checksum=?7,cache_key_fp=?8,version=?9,deleted_at=?10,updated_at=?11,sync_status=?12,metadata=?13
             WHERE storage_id=?1 AND id=?2 AND vault_id=?14 AND path=?15 AND name=?16 AND type_id=?17 AND payload_enc=?18 AND checksum=?19 AND cache_key_fp IS ?20 AND version=?21 AND deleted_at IS ?22 AND updated_at=?23 AND sync_status=?24 AND metadata IS ?25",
            next.storage_id, next.id, &next.path, &next.name, &next.type_id, &next.payload_enc, &next.checksum,
            next.cache_key_fp.as_deref(), next.version, next.deleted_at, next.updated_at, next.sync_status.as_i32(), next.metadata.as_ref().map(sqlx_core::types::Json),
            expected.vault_id, &expected.path, &expected.name, &expected.type_id, &expected.payload_enc, &expected.checksum,
            expected.cache_key_fp.as_deref(), expected.version, expected.deleted_at, expected.updated_at, expected.sync_status.as_i32(), expected.metadata.as_ref().map(sqlx_core::types::Json)
        ).execute(&mut *tx).await?.rows_affected();
        if affected != 1 {
            tx.rollback().await?;
            return Ok(false);
        }
        if let Some(history) = history {
            LocalItemHistoryRepo::create_in(&mut tx, history).await?;
        }
        // The schema permits exactly one pending row per storage/item. Preserve
        // its original server base (or its not-yet-published Create) when editing.
        let first = query_as!((i32, Option<i64>),
            "SELECT operation,base_seq FROM pending_changes WHERE storage_id=?1 AND item_id=?2 LIMIT 1",
            next.storage_id, next.id).fetch_optional(&mut *tx).await?;
        query!(
            "DELETE FROM pending_changes WHERE storage_id=?1 AND item_id=?2",
            next.storage_id,
            next.id
        )
        .execute(&mut *tx)
        .await?;
        if let Some(pending) = pending {
            let mut merged = pending.clone();
            if let Some((operation, base_seq)) = first {
                if operation == ChangeType::Create.as_i32() {
                    merged.operation = ChangeType::Create;
                    merged.base_seq = None;
                } else if base_seq.is_some() {
                    merged.base_seq = base_seq;
                }
            }
            PendingChangeRepo::create_in(&mut tx, &merged).await?;
        }
        tx.commit().await?;
        Ok(true)
    }
}
