-- Rebuildable public RP projection. NULL denotes a queued encrypted row.
CREATE TABLE passkey_rp_index (
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    item_id BLOB NOT NULL,
    rp_id TEXT,
    PRIMARY KEY(storage_id,item_id)
);
CREATE INDEX idx_passkey_rp ON passkey_rp_index(storage_id,vault_id,rp_id,item_id);
INSERT INTO passkey_rp_index(storage_id,vault_id,item_id)
SELECT storage_id,vault_id,id FROM items_cache WHERE type_id='passkey' AND deleted_at IS NULL;
CREATE TRIGGER passkey_index_insert AFTER INSERT ON items_cache
WHEN NEW.type_id='passkey' AND NEW.deleted_at IS NULL BEGIN
  INSERT INTO passkey_rp_index(storage_id,vault_id,item_id) VALUES(NEW.storage_id,NEW.vault_id,NEW.id);
END;
CREATE TRIGGER passkey_index_update AFTER UPDATE OF payload_enc,vault_id,type_id,deleted_at ON items_cache
WHEN NEW.payload_enc != OLD.payload_enc OR NEW.vault_id != OLD.vault_id OR NEW.type_id != OLD.type_id OR NEW.deleted_at IS NOT OLD.deleted_at BEGIN
  DELETE FROM passkey_rp_index WHERE storage_id=OLD.storage_id AND item_id=OLD.id;
  INSERT INTO passkey_rp_index(storage_id,vault_id,item_id)
    SELECT NEW.storage_id,NEW.vault_id,NEW.id WHERE NEW.type_id='passkey' AND NEW.deleted_at IS NULL;
END;
CREATE TRIGGER passkey_index_delete AFTER DELETE ON items_cache BEGIN
  DELETE FROM passkey_rp_index WHERE storage_id=OLD.storage_id AND item_id=OLD.id;
END;
