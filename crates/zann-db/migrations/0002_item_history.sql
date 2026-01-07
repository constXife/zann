CREATE TABLE item_history (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    item_id BLOB NOT NULL,
    payload_enc BLOB NOT NULL,
    checksum TEXT NOT NULL,
    version INTEGER NOT NULL,
    change_type TEXT NOT NULL,
    changed_by_email TEXT NOT NULL,
    changed_by_name TEXT,
    changed_by_device_id BLOB,
    changed_by_device_name TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES local_vaults(id) ON DELETE CASCADE
);

CREATE INDEX idx_item_history_storage_item
    ON item_history(storage_id, item_id);

CREATE INDEX idx_item_history_storage_item_version
    ON item_history(storage_id, item_id, version);
