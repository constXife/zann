CREATE TABLE metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE storages (
    id BLOB PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('local_only', 'remote')),
    name TEXT NOT NULL,
    server_url TEXT,
    account_subject TEXT,
    server_name TEXT,
    server_fingerprint TEXT,
    personal_vaults_enabled INTEGER NOT NULL DEFAULT 1,
    auth_method TEXT CHECK (auth_method IN ('oidc', 'password'))
);

INSERT INTO storages (id, kind, name)
VALUES (X'00000000000000000000000000000000', 'local_only', 'Local');

CREATE TABLE local_vaults (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'personal',
    is_default INTEGER NOT NULL DEFAULT 0,
    vault_key_enc BLOB NOT NULL,
    key_wrap_type TEXT NOT NULL,
    last_synced_at INTEGER,
    server_seq INTEGER DEFAULT 0
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
    updated_at INTEGER NOT NULL,
    sync_status TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES local_vaults(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_items_cache_storage_vault_path
    ON items_cache(storage_id, vault_id, path);
CREATE INDEX idx_items_cache_storage_vault_id
    ON items_cache(storage_id, vault_id);

CREATE TABLE sync_cursors (
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    cursor TEXT,
    last_sync_at TEXT,
    PRIMARY KEY (storage_id, vault_id)
);

CREATE TABLE pending_changes (
    id BLOB PRIMARY KEY NOT NULL,
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    item_id BLOB NOT NULL,
    operation TEXT NOT NULL,
    payload_enc BLOB,
    checksum TEXT,
    path TEXT,
    name TEXT,
    type_id TEXT,
    base_seq INTEGER,
    created_at TEXT NOT NULL
);
