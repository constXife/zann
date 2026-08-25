-- Validate the dynamically typed legacy storage headers before this migration
-- searches, groups, or indexes any of them.  Every potentially large value is
-- inspected through SQLite's record metadata first; CASE ordering is
-- intentional and must remain lazy.
CREATE TABLE _zann_0002_storage_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO _zann_0002_storage_guard (valid)
SELECT 0
FROM storages
WHERE CASE
    WHEN typeof(id) != 'blob' THEN 1
    WHEN octet_length(id) != 16 THEN 1
    WHEN typeof(kind) != 'integer' THEN 1
    WHEN kind NOT IN (1, 2) THEN 1
    WHEN typeof(name) != 'text' THEN 1
    WHEN octet_length(name) NOT BETWEEN 1 AND 200 THEN 1
    WHEN server_url IS NOT NULL AND typeof(server_url) != 'text' THEN 1
    WHEN server_url IS NOT NULL AND octet_length(server_url) NOT BETWEEN 1 AND 2048 THEN 1
    WHEN server_name IS NOT NULL AND typeof(server_name) != 'text' THEN 1
    WHEN server_name IS NOT NULL AND octet_length(server_name) NOT BETWEEN 1 AND 512 THEN 1
    WHEN server_fingerprint IS NOT NULL AND typeof(server_fingerprint) != 'text' THEN 1
    WHEN server_fingerprint IS NOT NULL AND octet_length(server_fingerprint) NOT BETWEEN 1 AND 512 THEN 1
    WHEN account_subject IS NOT NULL AND typeof(account_subject) != 'text' THEN 1
    WHEN account_subject IS NOT NULL AND octet_length(account_subject) NOT BETWEEN 1 AND 512 THEN 1
    WHEN typeof(personal_vaults_enabled) != 'integer' THEN 1
    WHEN personal_vaults_enabled NOT IN (0, 1) THEN 1
    WHEN auth_method IS NOT NULL AND typeof(auth_method) != 'integer' THEN 1
    WHEN auth_method IS NOT NULL AND auth_method NOT IN (1, 2, 3) THEN 1
    ELSE 0
END = 1
LIMIT 1;

DROP TABLE _zann_0002_storage_guard;

ALTER TABLE sync_cursors
    ADD COLUMN last_seq INTEGER
    CHECK (last_seq IS NULL OR last_seq >= 1);

-- A durable logical identity is verified through the actual SQLite
-- connection.  It complements filesystem identity pinning: path/inode checks
-- alone cannot distinguish a byte-for-byte replacement copied onto the same
-- path after an open.
CREATE TABLE local_database_identity (
    singleton INTEGER PRIMARY KEY NOT NULL,
    instance_uuid BLOB NOT NULL,
    CHECK (typeof(singleton) = 'integer' AND singleton = 1),
    CHECK (typeof(instance_uuid) = 'blob' AND octet_length(instance_uuid) = 16)
);

INSERT INTO local_database_identity (singleton, instance_uuid)
VALUES (1, randomblob(16));

-- A remote projection is either completely unclaimed or carries one exact
-- repository/target/config generation.  Revision is an unsigned big-endian
-- BLOB so ordering is stable across the full u64 range without SQLite's
-- signed-integer coercions.
ALTER TABLE storages
    ADD COLUMN sync_config_repository_fp BLOB
    CHECK (
        CASE
            WHEN sync_config_repository_fp IS NULL THEN 1
            WHEN typeof(sync_config_repository_fp) != 'blob' THEN 0
            WHEN octet_length(sync_config_repository_fp) = 32 THEN 1
            ELSE 0
        END
    );

ALTER TABLE storages
    ADD COLUMN sync_stable_target_fp BLOB
    CHECK (
        CASE
            WHEN sync_stable_target_fp IS NULL THEN 1
            WHEN typeof(sync_stable_target_fp) != 'blob' THEN 0
            WHEN octet_length(sync_stable_target_fp) = 32 THEN 1
            ELSE 0
        END
    );

ALTER TABLE storages
    ADD COLUMN sync_config_revision BLOB
    CHECK (
        CASE
            WHEN sync_config_revision IS NULL THEN 1
            WHEN typeof(sync_config_revision) != 'blob' THEN 0
            WHEN octet_length(sync_config_revision) = 8 THEN 1
            ELSE 0
        END
    );

ALTER TABLE storages
    ADD COLUMN sync_config_content_fp BLOB
    CHECK (
        CASE
            WHEN sync_config_content_fp IS NULL THEN
                sync_config_repository_fp IS NULL
                AND sync_stable_target_fp IS NULL
                AND sync_config_revision IS NULL
            WHEN sync_config_repository_fp IS NULL OR sync_stable_target_fp IS NULL OR sync_config_revision IS NULL THEN 0
            WHEN typeof(sync_config_content_fp) != 'blob' THEN 0
            WHEN octet_length(sync_config_content_fp) = 32 THEN 1
            ELSE 0
        END
    );

CREATE TRIGGER storages_sync_generation_validate_insert
BEFORE INSERT ON storages
BEGIN
    SELECT CASE
        WHEN typeof(NEW.id) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.id) != 16
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.kind) != 'integer'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN NEW.kind NOT IN (1, 2)
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN NEW.sync_config_repository_fp IS NULL THEN CASE
            WHEN NEW.sync_stable_target_fp IS NOT NULL
                OR NEW.sync_config_revision IS NOT NULL
                OR NEW.sync_config_content_fp IS NOT NULL
                THEN RAISE(ABORT, 'invalid local storage generation row')
        END
        WHEN NEW.kind != 2
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_config_repository_fp) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_config_repository_fp) != 32
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_stable_target_fp) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_stable_target_fp) != 32
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_config_revision) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_config_revision) != 8
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_config_content_fp) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_config_content_fp) != 32
            THEN RAISE(ABORT, 'invalid local storage generation row')
    END;
END;

CREATE TRIGGER storages_sync_generation_validate_update
BEFORE UPDATE ON storages
BEGIN
    SELECT CASE
        WHEN typeof(NEW.id) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.id) != 16
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.kind) != 'integer'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN NEW.kind NOT IN (1, 2)
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN NEW.sync_config_repository_fp IS NULL THEN CASE
            WHEN NEW.sync_stable_target_fp IS NOT NULL
                OR NEW.sync_config_revision IS NOT NULL
                OR NEW.sync_config_content_fp IS NOT NULL
                THEN RAISE(ABORT, 'invalid local storage generation row')
        END
        WHEN NEW.kind != 2
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_config_repository_fp) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_config_repository_fp) != 32
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_stable_target_fp) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_stable_target_fp) != 32
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_config_revision) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_config_revision) != 8
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN typeof(NEW.sync_config_content_fp) != 'blob'
            THEN RAISE(ABORT, 'invalid local storage generation row')
        WHEN octet_length(NEW.sync_config_content_fp) != 32
            THEN RAISE(ABORT, 'invalid local storage generation row')
    END;
END;

-- Refuse to reinterpret or truncate legacy vault metadata. The guard table
-- makes the whole migration fail before schema changes when a pre-existing
-- name, key envelope, or per-storage catalog is outside the v2 contract.
CREATE TABLE _zann_0002_local_vault_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO _zann_0002_local_vault_guard (valid)
SELECT 0
FROM local_vaults
WHERE CASE
    WHEN typeof(id) != 'blob' THEN 1
    WHEN octet_length(id) != 16 THEN 1
    WHEN typeof(storage_id) != 'blob' THEN 1
    WHEN octet_length(storage_id) != 16 THEN 1
    WHEN typeof(name) != 'text' THEN 1
    WHEN octet_length(name) NOT BETWEEN 1 AND 200 THEN 1
    WHEN typeof(vault_key_enc) != 'blob' THEN 1
    WHEN length(vault_key_enc) > 65536 THEN 1
    ELSE 0
END = 1
LIMIT 1;

INSERT INTO _zann_0002_local_vault_guard (valid)
SELECT 0
FROM local_vaults
GROUP BY storage_id
HAVING COUNT(*) > 200
LIMIT 1;

DROP TABLE _zann_0002_local_vault_guard;

ALTER TABLE local_vaults
    ADD COLUMN slug TEXT
    CHECK (
        slug IS NULL
        OR CASE
            WHEN typeof(slug) != 'text' THEN 0
            WHEN octet_length(slug) NOT BETWEEN 1 AND 128 THEN 0
            WHEN length(slug) != octet_length(slug) THEN 0
            WHEN slug NOT GLOB '*[^A-Za-z0-9_-]*' THEN 1
            WHEN octet_length(slug) != 39 THEN 0
            WHEN substr(slug, 1, 7) != 'local::' THEN 0
            WHEN substr(slug, 8) GLOB '*[^0-9a-f]*' THEN 0
            ELSE 1
        END
    );

ALTER TABLE local_vaults
    ADD COLUMN cache_key_fp TEXT
    CHECK (
        cache_key_fp IS NULL
        OR CASE
            WHEN typeof(cache_key_fp) != 'text' THEN 0
            WHEN octet_length(cache_key_fp) != 12 THEN 0
            WHEN length(cache_key_fp) != octet_length(cache_key_fp) THEN 0
            WHEN cache_key_fp GLOB '*[^0-9a-f]*' THEN 0
            ELSE 1
        END
    );

-- A deterministic internal slug preserves every legacy row without treating
-- its mutable display name as identity.
UPDATE local_vaults
SET slug = 'local::' || lower(hex(id));

DROP INDEX idx_local_vaults_storage_name;
CREATE INDEX idx_local_vaults_storage_name
    ON local_vaults(storage_id, name);
CREATE UNIQUE INDEX idx_local_vaults_storage_slug
    ON local_vaults(storage_id, slug);

-- SQLite cannot add a NOT NULL column to a populated table without a static
-- default. These triggers enforce the complete row contract for every future
-- insert and relevant update while allowing the deterministic backfill above.
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

-- Defense in depth for writers outside LocalVaultRepo. SQLite serializes the
-- trigger and insert in the same writer transaction, so two concurrent raw
-- writers cannot both cross the hard per-storage catalog bound.
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

-- Moving an existing row between storage catalogs must obey the same hard
-- cap as INSERT. This trigger is independently safe if it runs before the
-- general validation trigger: it touches the target catalog only after the
-- dynamic NEW/OLD storage identifiers are proven fixed-size BLOB UUIDs.
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
