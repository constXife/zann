-- Stream a selected vault in list order without sorting encrypted payloads.
CREATE INDEX idx_items_cache_vault_list ON items_cache(storage_id, vault_id, updated_at DESC, id DESC);
-- The leading columns also cover the previous vault-only index.
DROP INDEX idx_items_cache_storage_vault_id;
