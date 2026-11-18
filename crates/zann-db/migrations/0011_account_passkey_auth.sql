-- Add the canonical passkey auth method without changing prior checksums.
-- SQLx executes this rebuild atomically. No ciphertext/cache/key rows change,
-- and no foreign-key or schema-validation pragma is disabled.
-- Validate the dynamically typed legacy storage headers before this migration
-- searches, groups, or indexes any of them.  Every potentially large value is
-- inspected through SQLite's record metadata first; CASE ordering is
-- intentional and must remain lazy.
CREATE TABLE _zann_0011_storage_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO _zann_0011_storage_guard (valid)
SELECT 0
FROM storages
WHERE CASE
    WHEN typeof(id) != 'blob' THEN 1
    WHEN octet_length(id) != 16 THEN 1
    WHEN id = zeroblob(16) THEN 1
    WHEN typeof(kind) != 'integer' THEN 1
    WHEN kind != 2 THEN 1
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
    WHEN auth_method IS NOT NULL AND auth_method NOT IN (1, 2, 3, 4) THEN 1
    WHEN sync_config_repository_fp IS NOT NULL AND (typeof(sync_config_repository_fp) != 'blob' OR octet_length(sync_config_repository_fp) != 32) THEN 1
    WHEN sync_stable_target_fp IS NOT NULL AND (typeof(sync_stable_target_fp) != 'blob' OR octet_length(sync_stable_target_fp) != 32) THEN 1
    WHEN sync_config_revision IS NOT NULL AND (typeof(sync_config_revision) != 'blob' OR octet_length(sync_config_revision) != 8) THEN 1
    WHEN sync_config_content_fp IS NOT NULL AND (typeof(sync_config_content_fp) != 'blob' OR octet_length(sync_config_content_fp) != 32) THEN 1
    ELSE 0
END = 1
LIMIT 1;

INSERT INTO _zann_0011_storage_guard(valid)
SELECT 0 WHERE (SELECT COUNT(*) FROM (SELECT 1 FROM storages LIMIT 257)) > 256;
DROP TABLE _zann_0011_storage_guard;


CREATE TABLE storages_next (
    id BLOB PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    name TEXT NOT NULL,
    server_url TEXT,
    account_subject TEXT,
    server_name TEXT,
    server_fingerprint TEXT,
    personal_vaults_enabled INTEGER NOT NULL DEFAULT 1,
    auth_method INTEGER CHECK (auth_method IN (1, 2, 3, 4)), sync_config_repository_fp BLOB
    CHECK (
        CASE
            WHEN sync_config_repository_fp IS NULL THEN 1
            WHEN typeof(sync_config_repository_fp) != 'blob' THEN 0
            WHEN octet_length(sync_config_repository_fp) = 32 THEN 1
            ELSE 0
        END
    ), sync_stable_target_fp BLOB
    CHECK (
        CASE
            WHEN sync_stable_target_fp IS NULL THEN 1
            WHEN typeof(sync_stable_target_fp) != 'blob' THEN 0
            WHEN octet_length(sync_stable_target_fp) = 32 THEN 1
            ELSE 0
        END
    ), sync_config_revision BLOB
    CHECK (
        CASE
            WHEN sync_config_revision IS NULL THEN 1
            WHEN typeof(sync_config_revision) != 'blob' THEN 0
            WHEN octet_length(sync_config_revision) = 8 THEN 1
            ELSE 0
        END
    ), sync_config_content_fp BLOB
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
    ),
    CHECK (length(id) = 16),
    CHECK (
        (kind = 1 AND server_url IS NULL AND account_subject IS NULL AND server_name IS NULL AND server_fingerprint IS NULL AND auth_method IS NULL)
        OR
        (kind = 2 AND server_url IS NOT NULL)
    )
);
INSERT INTO storages_next (id,kind,name,server_url,account_subject,server_name,server_fingerprint,personal_vaults_enabled,auth_method,sync_config_repository_fp,sync_stable_target_fp,sync_config_revision,sync_config_content_fp)
SELECT id,kind,name,server_url,account_subject,server_name,server_fingerprint,personal_vaults_enabled,auth_method,sync_config_repository_fp,sync_stable_target_fp,sync_config_revision,sync_config_content_fp FROM storages;
DROP TABLE storages;
ALTER TABLE storages_next RENAME TO storages;

CREATE UNIQUE INDEX idx_storages_server_account ON storages(server_url, account_subject)
    WHERE kind = 2 AND server_url IS NOT NULL AND account_subject IS NOT NULL;

CREATE INDEX idx_storages_server_url ON storages(server_url)
    WHERE server_url IS NOT NULL;

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
