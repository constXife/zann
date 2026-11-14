use super::*;
use zann_core::ItemDetail;

#[derive(Debug, thiserror::Error)]
pub enum BrowserReadError {
    #[error("browser page query failed")]
    Database(#[from] sqlx_core::Error),
    #[error("browser payload read failed")]
    Payload(#[from] ServiceError),
}

impl LocalServices<'_> {
    pub async fn browser_login_page(
        &self,
        storage: Uuid,
        vault: Uuid,
        after: Option<Uuid>,
    ) -> Result<(Vec<ItemDetail>, Option<Uuid>), BrowserReadError> {
        let mut rows = LocalItemRepo::new(self.pool)
            .browser_login_page(storage, vault, after)
            .await?;
        let next = if rows.len() > zann_core::BROWSER_PAGE_LIMIT as usize {
            rows.pop();
            rows.last().map(|item| item.id)
        } else {
            None
        };
        let keys = self.vault_payload_keys(storage, vault).await?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let payload = self.open_payload(&keys, row.id, &row.payload_enc)?;
            items.push(ItemDetail {
                id: row.id,
                vault_id: row.vault_id,
                path: row.path,
                name: row.name,
                type_id: row.type_id,
                payload,
                updated_at: row.updated_at,
                version: row.version,
            });
        }
        Ok((items, next))
    }
}
