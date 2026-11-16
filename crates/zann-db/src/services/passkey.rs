//! Rebuildable RP projection and bounded ceremony reads under one writer/key lease.
use super::item_batch::PreparedItemBatch;
use super::*;
use crate::local::LocalItem;
use sqlx_core::query_as::query_as;
type Error = Box<dyn std::error::Error + Send + Sync>;
const COLUMNS: &str = r#"
SELECT i.id,i.storage_id,i.vault_id,
    CASE WHEN octet_length(i.path)<=500 THEN i.path END AS path,
    CASE WHEN octet_length(i.name)<=200 THEN i.name END AS name,i.type_id,
    CASE WHEN length(i.payload_enc)<=262400 THEN i.payload_enc END AS payload_enc,
    CASE WHEN octet_length(i.checksum)<=256 THEN i.checksum END AS checksum,
    CASE WHEN i.cache_key_fp IS NULL OR octet_length(i.cache_key_fp)=12
        THEN i.cache_key_fp ELSE 'invalid' END AS cache_key_fp,
    i.version,i.deleted_at,
    CASE WHEN octet_length(i.updated_at)<=64 THEN i.updated_at END AS updated_at,
    i.sync_status,
    CASE WHEN i.metadata IS NULL OR octet_length(i.metadata)<=65536
        THEN i.metadata ELSE 'invalid' END AS metadata
FROM passkey_rp_index p INDEXED BY idx_passkey_rp CROSS JOIN items_cache i
    ON i.storage_id=p.storage_id AND i.id=p.item_id AND i.vault_id=p.vault_id
WHERE p.storage_id=? AND p.vault_id=? AND i.type_id='passkey' AND i.deleted_at IS NULL
"#;
impl PreparedItemBatch {
    fn passkey_payload(&self, item: &LocalItem) -> Result<EncryptedPayload, Error> {
        if item.checksum != core_crypto::payload_checksum(&item.payload_enc) {
            return Err("passkey checksum mismatch".into());
        }
        let bytes = Zeroizing::new(core_crypto::decrypt_payload_bytes(
            &self.key,
            self.vault.id,
            item.id,
            &item.payload_enc,
        )?);
        Ok(EncryptedPayload::from_bytes(&bytes)?)
    }
    /// Old/unprojected rows are repaired in a bounded batch. Never silently
    /// truncate discovery/exclusion: an excessive backlog fails the operation.
    pub async fn read_passkeys(
        &mut self,
        rp: &str,
        max_index_rows: usize,
    ) -> Result<Vec<(LocalItem, EncryptedPayload)>, Error> {
        let limit = zann_core::BROWSER_PAGE_LIMIT as usize;
        let lookahead = limit + 1;
        let mut repaired = 0usize;
        loop {
            let missing: Vec<LocalItem> = query_as(&format!(
                "{COLUMNS} AND p.rp_id IS NULL ORDER BY p.item_id LIMIT {lookahead}"
            ))
            .bind(self.vault.storage_id)
            .bind(self.vault.id)
            .fetch_all(&mut *self.transaction)
            .await?;
            if missing.is_empty() {
                break;
            }
            let has_more = missing.len() > limit;
            let count = missing.len().min(limit);
            repaired = repaired
                .checked_add(count)
                .ok_or("passkey projection repair bound")?;
            if repaired > max_index_rows {
                return Err("passkey projection repair bound exceeded".into());
            }
            for item in missing.into_iter().take(limit) {
                let payload = self.passkey_payload(&item)?;
                let rp = zann_core::item_policy::passkey_rp_projection(&payload)
                    .ok_or("invalid passkey RP projection")?;
                sqlx_core::query::query(
                    "UPDATE passkey_rp_index SET rp_id=? WHERE storage_id=? AND item_id=?",
                )
                .bind(rp)
                .bind(self.vault.storage_id)
                .bind(item.id)
                .execute(&mut *self.transaction)
                .await?;
            }
            if !has_more {
                break;
            }
        }
        let rows: Vec<LocalItem> = query_as(&format!(
            "{COLUMNS} AND p.rp_id=? ORDER BY p.item_id LIMIT {lookahead}"
        ))
        .bind(self.vault.storage_id)
        .bind(self.vault.id)
        .bind(rp)
        .fetch_all(&mut *self.transaction)
        .await?;
        if rows.len() > limit {
            return Err("passkey candidate bound exceeded".into());
        }
        rows.into_iter()
            .map(|item| {
                let payload = self.passkey_payload(&item)?;
                Ok((item, payload))
            })
            .collect()
    }
}
