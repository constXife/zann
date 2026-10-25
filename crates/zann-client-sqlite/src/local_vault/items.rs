use super::*;

impl LocalVault {
    pub fn items_list(&self, filter: ItemsFilter, page: Page) -> LocalResult<ItemPage> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let pool = self.pool();
        let services = LocalServices::new(&pool, master_key.as_ref());
        let params = ItemListParams {
            query: filter.query,
            limit: Some(page.limit),
            cursor: page.cursor,
            include_deleted: filter.include_deleted,
        };
        let result =
            self.runtime_block_on(services.list_items(self.storage_id(), vault_id, params))?;
        Ok(ItemPage {
            items: result
                .items
                .into_iter()
                .map(|item| ItemSummary {
                    id: item.id.to_string(),
                    title: item.name,
                    path: item.path,
                    type_id: item.type_id,
                    deleted: item.deleted_at.is_some(),
                })
                .collect(),
            next_cursor: result.next_cursor,
            total_count: result.total_count as u64,
            counts: map_counts(result.counts),
        })
    }

    pub fn item_get(&self, id: String) -> LocalResult<ItemDetail> {
        let master_key = self.master_key()?;
        let _vault_id = self.vault_id()?;
        let pool = self.pool();
        let services = LocalServices::new(&pool, master_key.as_ref());
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid item id".to_string()))?;
        let item = self.runtime_block_on(services.get_item(self.storage_id(), item_id))?;
        let payload_json = serde_json::to_string(&item.payload)
            .map_err(|err| LocalError::Service(err.to_string()))?;
        Ok(ItemDetail {
            id: item.id.to_string(),
            title: item.name,
            path: item.path,
            type_id: item.type_id,
            payload_json,
        })
    }

    pub fn item_create(&self, create: ItemCreate) -> LocalResult<ItemDetail> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let pool = self.pool();
        let services = LocalServices::new(&pool, master_key.as_ref());
        let mut payload: EncryptedPayload =
            EncryptedPayload::from_bytes(create.payload_json.as_bytes())
                .map_err(LocalError::InvalidPayload)?;
        // The request is the source of truth. Keeping the encrypted payload's
        // discriminator aligned prevents clients from creating an item whose
        // list type and decrypted type disagree.
        payload.type_id = create.type_id.clone();
        let item_id = self.runtime_block_on(services.put_item(
            self.storage_id(),
            vault_id,
            create.path,
            create.type_id,
            payload,
        ))?;
        self.item_get(item_id.to_string())
    }

    pub fn item_update(&self, id: String, update: ItemUpdate) -> LocalResult<ItemDetail> {
        let master_key = self.master_key()?;
        let _vault_id = self.vault_id()?;
        let pool = self.pool();
        let services = LocalServices::new(&pool, master_key.as_ref());
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid item id".to_string()))?;
        let mut payload: EncryptedPayload =
            EncryptedPayload::from_bytes(update.payload_json.as_bytes())
                .map_err(LocalError::InvalidPayload)?;
        payload.type_id = update.type_id.clone();
        self.runtime
            .block_on(services.update_item_by_id(
                self.storage_id(),
                item_id,
                update.path,
                update.type_id,
                payload,
            ))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        self.item_get(id)
    }

    pub fn item_history_list(
        &self,
        id: String,
        limit: u32,
    ) -> LocalResult<Vec<ItemHistorySummary>> {
        let _master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid item id".to_string()))?;
        let pool = self.pool();
        let item = self
            .runtime
            .block_on(LocalItemRepo::new(&pool).get_by_id(self.storage_id(), item_id))
            .map_err(|err| LocalError::Service(err.to_string()))?
            .ok_or_else(|| LocalError::InvalidArgument("item not found".to_string()))?;
        if item.vault_id != vault_id {
            return Err(LocalError::InvalidArgument(
                "item is not in the current vault".to_string(),
            ));
        }
        let limit = i64::from(limit.clamp(1, 50));
        let history = self
            .runtime
            .block_on(LocalItemHistoryRepo::new(&pool).list_by_item_limit(
                self.storage_id(),
                item_id,
                limit,
            ))
            .map_err(|err| LocalError::Service(err.to_string()))?;
        Ok(history
            .into_iter()
            .map(|entry| ItemHistorySummary {
                version: entry.version,
                checksum: entry.checksum,
                change_type: entry.change_type.as_i32(),
                changed_by_name: entry.changed_by_name,
                changed_by_email: entry.changed_by_email,
                created_at: entry.created_at.to_rfc3339(),
                pending: entry.sync_status == HistorySyncStatus::Pending,
            })
            .collect())
    }

    pub fn item_history_get(&self, id: String, version: i64) -> LocalResult<ItemHistoryDetail> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid item id".to_string()))?;
        let pool = self.pool();
        let history = self
            .runtime
            .block_on(LocalItemHistoryRepo::new(&pool).get_by_item_version(
                self.storage_id(),
                item_id,
                version,
            ))
            .map_err(|err| LocalError::Service(err.to_string()))?
            .ok_or_else(|| LocalError::InvalidArgument("history not found".to_string()))?;
        if history.vault_id != vault_id {
            return Err(LocalError::InvalidArgument(
                "item is not in the current vault".to_string(),
            ));
        }
        let services = LocalServices::new(&pool, master_key.as_ref());
        let payload = self.runtime_block_on(services.decrypt_payload_for_item(
            self.storage_id(),
            vault_id,
            item_id,
            &history.payload_enc,
        ))?;
        let payload_json =
            serde_json::to_string(&payload).map_err(|err| LocalError::Service(err.to_string()))?;
        Ok(ItemHistoryDetail {
            version,
            payload_json,
        })
    }

    pub fn item_history_restore(&self, id: String, version: i64) -> LocalResult<ItemDetail> {
        let master_key = self.master_key()?;
        let vault_id = self.vault_id()?;
        let item_id = Uuid::parse_str(&id)
            .map_err(|_| LocalError::InvalidArgument("invalid item id".to_string()))?;
        let pool = self.pool();
        let item = self
            .runtime
            .block_on(LocalItemRepo::new(&pool).get_by_id(self.storage_id(), item_id))
            .map_err(|err| LocalError::Service(err.to_string()))?
            .ok_or_else(|| LocalError::InvalidArgument("item not found".to_string()))?;
        if item.vault_id != vault_id {
            return Err(LocalError::InvalidArgument(
                "item is not in the current vault".to_string(),
            ));
        }
        let services = LocalServices::new(&pool, master_key.as_ref());
        self.runtime_block_on(services.restore_item_version(self.storage_id(), item_id, version))?;
        self.item_get(id)
    }
}
