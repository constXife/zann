-- Re-key the local projection by `(storage_id, id)` so several remote
-- storages can keep server-assigned vault/item/history identifiers in one
-- client database without colliding.
--
-- Every existing row already has a globally unique id, so the copy below is
-- lossless. A child row whose storage differs from its vault's storage would
-- violate the new composite foreign key; refuse to reinterpret it and abort
-- the whole migration instead.
CREATE TABLE _zann_0003_reference_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO _zann_0003_reference_guard (valid)
SELECT 0
FROM items_cache AS item
WHERE NOT EXISTS (
    SELECT 1
    FROM local_vaults AS vault
    WHERE vault.id = item.vault_id AND vault.storage_id = item.storage_id
)
LIMIT 1;

INSERT INTO _zann_0003_reference_guard (valid)
SELECT 0
FROM item_history AS history
WHERE NOT EXISTS (
    SELECT 1
    FROM local_vaults AS vault
    WHERE vault.id = history.vault_id AND vault.storage_id = history.storage_id
)
LIMIT 1;

DROP TABLE _zann_0003_reference_guard;

CREATE TABLE local_vaults_v3 (
    id BLOB NOT NULL,
    storage_id BLOB NOT NULL,
    name TEXT NOT NULL,
    kind INTEGER NOT NULL DEFAULT 1 CHECK (kind IN (1, 2)),
    is_default INTEGER NOT NULL DEFAULT 0,
    vault_key_enc BLOB NOT NULL,
    key_wrap_type INTEGER NOT NULL CHECK (key_wrap_type IN (1, 2, 3)),
    last_synced_at INTEGER,
    slug TEXT NOT NULL
        CHECK (
            CASE
                WHEN typeof(slug) != 'text' THEN 0
                WHEN octet_length(slug) NOT BETWEEN 1 AND 128 THEN 0
                WHEN length(slug) != octet_length(slug) THEN 0
                WHEN slug NOT GLOB '*[^A-Za-z0-9_-]*' THEN 1
                WHEN octet_length(slug) != 39 THEN 0
                WHEN substr(slug, 1, 7) != 'local::' THEN 0
                WHEN substr(slug, 8) GLOB '*[^0-9a-f]*' THEN 0
                ELSE 1
            END
        ),
    cache_key_fp TEXT
        CHECK (
            cache_key_fp IS NULL
            OR CASE
                WHEN typeof(cache_key_fp) != 'text' THEN 0
                WHEN octet_length(cache_key_fp) != 12 THEN 0
                WHEN length(cache_key_fp) != octet_length(cache_key_fp) THEN 0
                WHEN cache_key_fp GLOB '*[^0-9a-f]*' THEN 0
                ELSE 1
            END
        ),
    PRIMARY KEY (storage_id, id),
    CHECK (length(id) = 16),
    CHECK (length(storage_id) = 16)
);

CREATE TABLE items_cache_v3 (
    id BLOB NOT NULL,
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
    PRIMARY KEY (storage_id, id),
    FOREIGN KEY (storage_id, vault_id)
        REFERENCES local_vaults_v3(storage_id, id) ON DELETE CASCADE,
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

CREATE TABLE item_history_v3 (
    id BLOB NOT NULL,
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
    source INTEGER NOT NULL DEFAULT 1 CHECK (source IN (1, 2, 3)),
    sync_status INTEGER NOT NULL DEFAULT 2 CHECK (sync_status IN (1, 2, 3)),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (storage_id, id),
    FOREIGN KEY (storage_id, vault_id)
        REFERENCES local_vaults_v3(storage_id, id) ON DELETE CASCADE,
    CHECK (length(id) = 16),
    CHECK (length(storage_id) = 16),
    CHECK (length(vault_id) = 16),
    CHECK (length(item_id) = 16),
    CHECK (changed_by_device_id IS NULL OR length(changed_by_device_id) = 16)
);

INSERT INTO local_vaults_v3 (
    id, storage_id, name, kind, is_default, vault_key_enc, key_wrap_type,
    last_synced_at, slug, cache_key_fp
)
SELECT
    id, storage_id, name, kind, is_default, vault_key_enc, key_wrap_type,
    last_synced_at, slug, cache_key_fp
FROM local_vaults;

-- Preserve rowids: `items_cache_fts` is an external-content index keyed by
-- `items_cache.rowid`, so the existing full-text index stays exact.
INSERT INTO items_cache_v3 (
    rowid, id, storage_id, vault_id, path, name, type_id, payload_enc, checksum,
    cache_key_fp, version, deleted_at, updated_at, sync_status
)
SELECT
    rowid, id, storage_id, vault_id, path, name, type_id, payload_enc, checksum,
    cache_key_fp, version, deleted_at, updated_at, sync_status
FROM items_cache;

INSERT INTO item_history_v3 (
    id, storage_id, vault_id, item_id, payload_enc, checksum, version,
    change_type, changed_by_email, changed_by_name, changed_by_device_id,
    changed_by_device_name, source, sync_status, created_at
)
SELECT
    id, storage_id, vault_id, item_id, payload_enc, checksum, version,
    change_type, changed_by_email, changed_by_name, changed_by_device_id,
    changed_by_device_name, source, sync_status, created_at
FROM item_history;

-- Children first: with foreign keys enabled, DROP TABLE performs an implicit
-- DELETE, and dropping the old parent while old children still exist would
-- cascade through them. The implicit DELETE does not fire triggers, so the
-- full-text index is untouched.
DROP TABLE item_history;
DROP TABLE items_cache;
DROP TABLE local_vaults;

-- RENAME rewrites the child foreign keys that name `local_vaults_v3`.
ALTER TABLE local_vaults_v3 RENAME TO local_vaults;
ALTER TABLE items_cache_v3 RENAME TO items_cache;
ALTER TABLE item_history_v3 RENAME TO item_history;

CREATE INDEX idx_local_vaults_storage_name
    ON local_vaults(storage_id, name);
CREATE UNIQUE INDEX idx_local_vaults_storage_slug
    ON local_vaults(storage_id, slug);

CREATE UNIQUE INDEX idx_items_cache_storage_vault_path
    ON items_cache(storage_id, vault_id, path)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_items_cache_storage_vault_id
    ON items_cache(storage_id, vault_id);

CREATE INDEX idx_item_history_storage_item
    ON item_history(storage_id, item_id);
CREATE INDEX idx_item_history_storage_item_version
    ON item_history(storage_id, item_id, version);
CREATE INDEX idx_item_history_storage_vault
    ON item_history(storage_id, vault_id);

CREATE TRIGGER items_cache_fts_insert
AFTER INSERT ON items_cache
BEGIN
    INSERT INTO items_cache_fts(rowid, name, path, type_id)
    VALUES (new.rowid, new.name, new.path, new.type_id);
END;

CREATE TRIGGER items_cache_fts_delete
AFTER DELETE ON items_cache
BEGIN
    INSERT INTO items_cache_fts(items_cache_fts, rowid, name, path, type_id)
    VALUES ('delete', old.rowid, old.name, old.path, old.type_id);
END;

CREATE TRIGGER items_cache_fts_update
AFTER UPDATE ON items_cache
BEGIN
    INSERT INTO items_cache_fts(items_cache_fts, rowid, name, path, type_id)
    VALUES ('delete', old.rowid, old.name, old.path, old.type_id);
    INSERT INTO items_cache_fts(rowid, name, path, type_id)
    VALUES (new.rowid, new.name, new.path, new.type_id);
END;

-- The v2 row contract and per-storage catalog bound are table triggers, so
-- they are recreated unchanged for the rebuilt table.
CREATE TRIGGER local_vaults_v2_validate_insert
BEFORE INSERT ON local_vaults
BEGIN
    SELECT CASE
        WHEN typeof(NEW.id) != 'blob'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.id) != 16
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.storage_id) != 'blob'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.storage_id) != 16
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.name) != 'text'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.name) NOT BETWEEN 1 AND 200
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.kind) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.kind NOT IN (1, 2)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.is_default) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.is_default NOT IN (0, 1)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.vault_key_enc) != 'blob'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN length(NEW.vault_key_enc) > 65536
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.key_wrap_type) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.key_wrap_type NOT IN (1, 2, 3)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.last_synced_at IS NOT NULL AND typeof(NEW.last_synced_at) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.slug IS NULL
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.slug) != 'text'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.slug) NOT BETWEEN 1 AND 128
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN length(NEW.slug) != octet_length(NEW.slug)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NOT (
            NEW.slug NOT GLOB '*[^A-Za-z0-9_-]*'
            OR (
                octet_length(NEW.slug) = 39
                AND substr(NEW.slug, 1, 7) = 'local::'
                AND substr(NEW.slug, 8) NOT GLOB '*[^0-9a-f]*'
            )
        ) THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.cache_key_fp IS NOT NULL THEN CASE
            WHEN typeof(NEW.cache_key_fp) != 'text'
                THEN RAISE(ABORT, 'invalid local vault persistence row')
            WHEN octet_length(NEW.cache_key_fp) != 12
                THEN RAISE(ABORT, 'invalid local vault persistence row')
            WHEN length(NEW.cache_key_fp) != octet_length(NEW.cache_key_fp)
                THEN RAISE(ABORT, 'invalid local vault persistence row')
            WHEN NEW.cache_key_fp GLOB '*[^0-9a-f]*'
                THEN RAISE(ABORT, 'invalid local vault persistence row')
        END
    END;
END;

CREATE TRIGGER local_vaults_v2_limit_insert
BEFORE INSERT ON local_vaults
WHEN CASE
    WHEN typeof(NEW.storage_id) != 'blob' THEN 0
    WHEN octet_length(NEW.storage_id) != 16 THEN 0
    ELSE (
        SELECT COUNT(*)
        FROM local_vaults
        WHERE storage_id = NEW.storage_id
    ) >= 200
END
BEGIN
    SELECT RAISE(ABORT, 'local vault count exceeds the supported range');
END;

CREATE TRIGGER local_vaults_v2_limit_storage_update
BEFORE UPDATE OF storage_id ON local_vaults
WHEN CASE
    WHEN typeof(NEW.storage_id) != 'blob' THEN 0
    WHEN octet_length(NEW.storage_id) != 16 THEN 0
    WHEN typeof(OLD.storage_id) != 'blob' THEN 0
    WHEN octet_length(OLD.storage_id) != 16 THEN 0
    WHEN NEW.storage_id = OLD.storage_id THEN 0
    ELSE (
        SELECT COUNT(*)
        FROM local_vaults
        WHERE storage_id = NEW.storage_id
    ) >= 200
END
BEGIN
    SELECT RAISE(ABORT, 'local vault count exceeds the supported range');
END;

CREATE TRIGGER local_vaults_v2_validate_update
BEFORE UPDATE ON local_vaults
BEGIN
    SELECT CASE
        WHEN typeof(NEW.id) != 'blob'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.id) != 16
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.storage_id) != 'blob'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.storage_id) != 16
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.name) != 'text'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.name) NOT BETWEEN 1 AND 200
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.kind) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.kind NOT IN (1, 2)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.is_default) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.is_default NOT IN (0, 1)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.vault_key_enc) != 'blob'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN length(NEW.vault_key_enc) > 65536
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.key_wrap_type) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.key_wrap_type NOT IN (1, 2, 3)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.last_synced_at IS NOT NULL AND typeof(NEW.last_synced_at) != 'integer'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.slug IS NULL
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN typeof(NEW.slug) != 'text'
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN octet_length(NEW.slug) NOT BETWEEN 1 AND 128
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN length(NEW.slug) != octet_length(NEW.slug)
            THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NOT (
            NEW.slug NOT GLOB '*[^A-Za-z0-9_-]*'
            OR (
                octet_length(NEW.slug) = 39
                AND substr(NEW.slug, 1, 7) = 'local::'
                AND substr(NEW.slug, 8) NOT GLOB '*[^0-9a-f]*'
            )
        ) THEN RAISE(ABORT, 'invalid local vault persistence row')
        WHEN NEW.cache_key_fp IS NOT NULL THEN CASE
            WHEN typeof(NEW.cache_key_fp) != 'text'
                THEN RAISE(ABORT, 'invalid local vault persistence row')
            WHEN octet_length(NEW.cache_key_fp) != 12
                THEN RAISE(ABORT, 'invalid local vault persistence row')
            WHEN length(NEW.cache_key_fp) != octet_length(NEW.cache_key_fp)
                THEN RAISE(ABORT, 'invalid local vault persistence row')
            WHEN NEW.cache_key_fp GLOB '*[^0-9a-f]*'
                THEN RAISE(ABORT, 'invalid local vault persistence row')
        END
    END;
END;
