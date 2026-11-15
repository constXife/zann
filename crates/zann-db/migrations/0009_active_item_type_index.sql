-- Bounded type-scoped scans for local exchange; credential identities remain encrypted.
CREATE INDEX idx_items_cache_active_type ON items_cache(storage_id,vault_id,type_id,id)
WHERE deleted_at IS NULL;
