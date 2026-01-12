CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE storages (
    id BLOB PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    name TEXT NOT NULL,
    server_url TEXT,
    account_subject TEXT,
    server_name TEXT,
    server_fingerprint TEXT,
    personal_vaults_enabled INTEGER NOT NULL DEFAULT 1,
    auth_method INTEGER CHECK (auth_method IN (1, 2, 3)),
    CHECK (length(id) = 16),
    CHECK (
        (kind = 1 AND server_url IS NULL AND account_subject IS NULL AND server_name IS NULL AND server_fingerprint IS NULL AND auth_method IS NULL)
        OR
        (kind = 2 AND server_url IS NOT NULL)
    )
);

CREATE UNIQUE INDEX idx_storages_server_url
    ON storages(server_url)
    WHERE server_url IS NOT NULL;

INSERT INTO storages (id, kind, name)
VALUES (X'00000000000000000000000000000000', 1, 'Local');

CREATE TABLE local_vaults (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    name TEXT NOT NULL,
    kind INTEGER NOT NULL DEFAULT 1 CHECK (kind IN (1, 2)),
    is_default INTEGER NOT NULL DEFAULT 0,
    vault_key_enc BLOB NOT NULL,
    key_wrap_type INTEGER NOT NULL CHECK (key_wrap_type IN (1, 2, 3)),
    last_synced_at INTEGER,
    CHECK (length(id) = 16),
    CHECK (length(storage_id) = 16)
);

CREATE UNIQUE INDEX idx_local_vaults_storage_name ON local_vaults(storage_id, name);
CREATE INDEX idx_local_vaults_storage_id ON local_vaults(storage_id);

CREATE TABLE items_cache (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    type_id TEXT NOT NULL,
    payload_enc BLOB NOT NULL,
    checksum TEXT NOT NULL,
    cache_key_fp TEXT,
    version INTEGER NOT NULL,
    deleted_at INTEGER,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    sync_status INTEGER NOT NULL CHECK (sync_status IN (1, 2, 3, 4, 5, 6)),
    FOREIGN KEY (vault_id) REFERENCES local_vaults(id) ON DELETE CASCADE,
    CHECK (length(id) = 16),
    CHECK (length(storage_id) = 16),
    CHECK (length(vault_id) = 16),
    CHECK (length(name) <= 200),
    CHECK (length(path) <= 500),
    CHECK (
        path NOT LIKE '.%' AND
        path NOT LIKE '%/.%' AND
        path NOT LIKE '%//%' AND
        path NOT LIKE './%' AND
        path NOT LIKE '%/./%' AND
        path <> '..' AND
        path NOT LIKE '../%' AND
        path NOT LIKE '%/../%' AND
        path NOT LIKE '%/..'
    )
);

CREATE UNIQUE INDEX idx_items_cache_storage_vault_path
    ON items_cache(storage_id, vault_id, path)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_items_cache_storage_vault_id
    ON items_cache(storage_id, vault_id);

CREATE TABLE item_history (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    item_id BLOB NOT NULL,
    payload_enc BLOB NOT NULL,
    checksum TEXT NOT NULL,
    version INTEGER NOT NULL,
    change_type INTEGER NOT NULL CHECK (change_type IN (1, 2, 3, 4)),
    changed_by_email TEXT NOT NULL,
    changed_by_name TEXT,
    changed_by_device_id BLOB,
    changed_by_device_name TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    FOREIGN KEY (vault_id) REFERENCES local_vaults(id) ON DELETE CASCADE,
    CHECK (length(id) = 16),
    CHECK (length(storage_id) = 16),
    CHECK (length(vault_id) = 16),
    CHECK (length(item_id) = 16),
    CHECK (changed_by_device_id IS NULL OR length(changed_by_device_id) = 16)
);

CREATE INDEX idx_item_history_storage_item
    ON item_history(storage_id, item_id);

CREATE INDEX idx_item_history_storage_item_version
    ON item_history(storage_id, item_id, version);

CREATE TABLE sync_cursors (
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    cursor TEXT,
    last_sync_at TEXT,
    PRIMARY KEY (storage_id, vault_id),
    CHECK (length(storage_id) = 16),
    CHECK (length(vault_id) = 16)
);

CREATE TABLE pending_changes (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    item_id BLOB NOT NULL,
    operation INTEGER NOT NULL CHECK (operation IN (1, 2, 3, 4)),
    payload_enc BLOB,
    checksum TEXT,
    path TEXT,
    name TEXT,
    type_id TEXT,
    base_seq INTEGER,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    CHECK (length(id) = 16),
    CHECK (length(storage_id) = 16),
    CHECK (length(vault_id) = 16),
    CHECK (length(item_id) = 16)
);

CREATE UNIQUE INDEX idx_pending_changes_storage_item
    ON pending_changes(storage_id, item_id);
CREATE INDEX idx_pending_changes_storage_vault_created
    ON pending_changes(storage_id, vault_id, created_at);
CREATE INDEX idx_pending_changes_storage_created
    ON pending_changes(storage_id, created_at);
