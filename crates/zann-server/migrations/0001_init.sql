CREATE TABLE users (
    id UUID PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT,
    password_hash TEXT,
    kdf_salt TEXT NOT NULL,
    kdf_algorithm TEXT NOT NULL DEFAULT 'argon2id',
    kdf_iterations BIGINT NOT NULL DEFAULT 3,
    kdf_memory_kb BIGINT NOT NULL DEFAULT 65536,
    kdf_parallelism BIGINT NOT NULL DEFAULT 4,
    recovery_key_hash TEXT,
    status SMALLINT NOT NULL DEFAULT 1,
    deleted_at TIMESTAMPTZ,
    deleted_by_user_id UUID,
    deleted_by_device_id UUID,
    row_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO users (
    id, email, full_name, status, kdf_salt, created_at, updated_at, last_login_at
)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    'system@zann.internal',
    'System',
    3,
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    now(),
    now(),
    NULL
);

CREATE TABLE oidc_identities (
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (issuer, subject),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_oidc_identities_user_id ON oidc_identities(user_id);

CREATE TABLE groups (
    id UUID PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE group_members (
    group_id UUID NOT NULL,
    user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_group_members_user_id ON group_members(user_id);

CREATE TABLE oidc_group_mappings (
    id UUID PRIMARY KEY NOT NULL,
    issuer TEXT NOT NULL,
    oidc_group TEXT NOT NULL,
    internal_group_id UUID NOT NULL,
    UNIQUE (issuer, oidc_group),
    FOREIGN KEY (internal_group_id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE TABLE devices (
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL,
    name TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT 'unknown',
    os TEXT,
    os_version TEXT,
    app_version TEXT,
    last_seen_at TIMESTAMPTZ,
    last_ip TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_devices_user_id ON devices(user_id);

CREATE TABLE sessions (
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL,
    device_id UUID NOT NULL,
    access_token_hash TEXT NOT NULL,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_device_id ON sessions(device_id);

CREATE TABLE service_accounts (
    id UUID PRIMARY KEY NOT NULL,
    owner_user_id UUID NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_ips JSONB,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_ip TEXT,
    last_used_user_agent TEXT,
    use_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_service_accounts_owner ON service_accounts(owner_user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_service_accounts_prefix ON service_accounts(token_prefix) WHERE revoked_at IS NULL;

CREATE TABLE service_account_sessions (
    id UUID PRIMARY KEY NOT NULL,
    service_account_id UUID NOT NULL,
    access_token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE
);

CREATE INDEX idx_service_account_sessions_sa ON service_account_sessions(service_account_id);
CREATE INDEX idx_service_account_sessions_token ON service_account_sessions(access_token_hash);

CREATE TABLE vaults (
    id UUID PRIMARY KEY NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    kind SMALLINT NOT NULL,
    encryption_type SMALLINT NOT NULL DEFAULT 1,
    vault_key_enc BYTEA NOT NULL,
    cache_policy SMALLINT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    deleted_at TIMESTAMPTZ,
    deleted_by_user_id UUID,
    deleted_by_device_id UUID,
    row_version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (deleted_by_device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE TABLE vault_members (
    vault_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role SMALLINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (vault_id, user_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_vault_members_user_id ON vault_members(user_id);

CREATE TABLE items (
    id UUID PRIMARY KEY NOT NULL,
    vault_id UUID NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    type_id TEXT NOT NULL,
    tags JSONB,
    favorite BOOLEAN NOT NULL,
    payload_enc BYTEA NOT NULL,
    checksum TEXT NOT NULL,
    version BIGINT NOT NULL,
    row_version BIGINT NOT NULL DEFAULT 1,
    device_id UUID NOT NULL,
    sync_status SMALLINT NOT NULL DEFAULT 1,
    deleted_at TIMESTAMPTZ,
    deleted_by_user_id UUID,
    deleted_by_device_id UUID,
    rotation_state TEXT,
    rotation_candidate_enc BYTEA,
    rotation_started_at TIMESTAMPTZ,
    rotation_started_by UUID,
    rotation_expires_at TIMESTAMPTZ,
    rotation_recover_until TIMESTAMPTZ,
    rotation_aborted_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT chk_sync_tombstone CHECK (
        (sync_status = 2 AND deleted_at IS NOT NULL) OR
        (sync_status = 1 AND deleted_at IS NULL)
    ),
    CONSTRAINT chk_deleted_by CHECK (
        (deleted_at IS NULL AND deleted_by_user_id IS NULL) OR
        (deleted_at IS NOT NULL AND deleted_by_user_id IS NOT NULL)
    ),
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT,
    FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (deleted_by_device_id) REFERENCES devices(id) ON DELETE SET NULL,
    FOREIGN KEY (rotation_started_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX idx_items_vault_path_active
    ON items(vault_id, path)
    WHERE sync_status = 1;
CREATE INDEX idx_items_vault_id ON items(vault_id);

CREATE TABLE item_usage (
    item_id UUID PRIMARY KEY NOT NULL,
    last_read_at TIMESTAMPTZ NOT NULL,
    last_read_by_user_id UUID,
    last_read_by_device_id UUID,
    read_count BIGINT NOT NULL DEFAULT 1,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    FOREIGN KEY (last_read_by_user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (last_read_by_device_id) REFERENCES devices(id) ON DELETE SET NULL
);

CREATE TABLE item_history (
    id UUID PRIMARY KEY NOT NULL,
    item_id UUID NOT NULL,
    version BIGINT NOT NULL,
    payload_enc BYTEA NOT NULL,
    checksum TEXT NOT NULL,
    change_type SMALLINT NOT NULL,
    fields_changed JSONB,
    changed_by_user_id UUID NOT NULL,
    changed_by_email TEXT NOT NULL,
    changed_by_name TEXT,
    changed_by_device_id UUID,
    changed_by_device_name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    FOREIGN KEY (changed_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (changed_by_device_id) REFERENCES devices(id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX idx_item_history_item_version ON item_history(item_id, version);
CREATE INDEX idx_item_history_item_id ON item_history(item_id);

CREATE TABLE attachments (
    id UUID PRIMARY KEY NOT NULL,
    item_id UUID NOT NULL,
    filename TEXT NOT NULL,
    size BIGINT NOT NULL,
    mime_type TEXT NOT NULL,
    enc_mode TEXT NOT NULL DEFAULT 'plain',
    content_enc BYTEA NOT NULL,
    checksum TEXT NOT NULL,
    storage_url TEXT,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE
);

CREATE INDEX idx_attachments_item_id ON attachments(item_id);
CREATE INDEX idx_attachments_deleted_at ON attachments(deleted_at);

CREATE TABLE changes (
    seq BIGSERIAL PRIMARY KEY,
    vault_id UUID NOT NULL,
    item_id UUID NOT NULL,
    op SMALLINT NOT NULL,
    version BIGINT NOT NULL,
    device_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT
);

CREATE INDEX idx_changes_vault_seq ON changes(vault_id, seq);
