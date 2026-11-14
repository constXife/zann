CREATE INDEX idx_items_browser_logins
ON items_cache(storage_id, vault_id, id)
WHERE type_id = 'login' AND deleted_at IS NULL;
