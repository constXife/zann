-- items_cache accepts epoch seconds (schema default) and UTC RFC3339 (client writes).
-- A single chronological key supports date bounds, ordering and page cursors for both.
DROP INDEX idx_items_cache_vault_list;
CREATE INDEX idx_items_cache_vault_list ON items_cache(
    storage_id, vault_id,
    (CASE typeof(updated_at) WHEN 'integer' THEN strftime('%Y-%m-%dT%H:%M:%S', updated_at, 'unixepoch') || '+00:00' ELSE updated_at END) DESC,
    id DESC
);
