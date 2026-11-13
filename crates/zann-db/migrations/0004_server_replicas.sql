-- Refuse to discard any legacy local-only data, including orphaned history
-- or pending changes. This migration runs in SQLx's transaction: failure
-- preserves both the old schema and every row. Use an older client to export
-- such a vault before upgrading; no automatic remapping of its KDF identity.
CREATE TABLE _zann_legacy_local_data_requires_export (
    valid INTEGER NOT NULL CONSTRAINT legacy_local_data_requires_export CHECK (valid = 1)
);
INSERT INTO _zann_legacy_local_data_requires_export (valid)
SELECT 0 WHERE
    EXISTS (SELECT 1 FROM local_vaults WHERE storage_id = zeroblob(16)
        OR storage_id IN (SELECT id FROM storages WHERE kind = 1))
    OR EXISTS (SELECT 1 FROM items_cache WHERE storage_id = zeroblob(16)
        OR storage_id IN (SELECT id FROM storages WHERE kind = 1))
    OR EXISTS (SELECT 1 FROM item_history WHERE storage_id = zeroblob(16)
        OR storage_id IN (SELECT id FROM storages WHERE kind = 1))
    OR EXISTS (SELECT 1 FROM pending_changes WHERE storage_id = zeroblob(16)
        OR storage_id IN (SELECT id FROM storages WHERE kind = 1));
DROP TABLE _zann_legacy_local_data_requires_export;

DELETE FROM sync_cursors WHERE storage_id = zeroblob(16)
    OR storage_id IN (SELECT id FROM storages WHERE kind = 1);
DELETE FROM storages WHERE kind = 1 OR id = zeroblob(16);

-- Keep historical migration checksums intact. After the forward cutover no
-- writer, including an older client, can recreate the standalone mode.
CREATE TRIGGER storages_server_only_insert
BEFORE INSERT ON storages
WHEN NEW.kind != 2 OR NEW.id = zeroblob(16)
BEGIN
    SELECT RAISE(ABORT, 'server storage required');
END;
CREATE TRIGGER storages_server_only_update
BEFORE UPDATE ON storages
WHEN NEW.kind != 2 OR NEW.id = zeroblob(16)
BEGIN
    SELECT RAISE(ABORT, 'server storage required');
END;
