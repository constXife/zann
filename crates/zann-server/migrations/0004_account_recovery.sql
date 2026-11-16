ALTER TABLE users
    ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    ADD COLUMN security_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    ADD COLUMN recovery_key_version BIGINT NOT NULL DEFAULT 0 CHECK (recovery_key_version >= 0),
    ADD COLUMN active_recovery_id UUID;
UPDATE users SET recovery_key_version = 1 WHERE recovery_key_hash IS NOT NULL;
ALTER TABLE sessions ADD COLUMN auth_epoch BIGINT NOT NULL DEFAULT 1 CHECK (auth_epoch > 0);
ALTER TABLE sessions ALTER COLUMN auth_epoch DROP DEFAULT;

CREATE TABLE account_recovery_operations (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    resume_token_hash TEXT NOT NULL CHECK (resume_token_hash ~ '^[0-9a-f]{64}$'),
    consume_digest BYTEA NOT NULL CHECK (octet_length(consume_digest) = 32),
    consumed_code_version BIGINT NOT NULL CHECK (consumed_code_version >= 1),
    successor_code_version BIGINT NOT NULL CHECK (successor_code_version = consumed_code_version + 1),
    auth_epoch BIGINT NOT NULL CHECK (auth_epoch > 0),
    account_key_epoch BIGINT CHECK (account_key_epoch > 0),
    state SMALLINT NOT NULL CHECK (state BETWEEN 1 AND 6),
    revision BIGINT NOT NULL CHECK (revision > 0),
    receipt_count SMALLINT NOT NULL DEFAULT 0 CHECK (receipt_count BETWEEN 0 AND 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL CHECK (expires_at = created_at + INTERVAL '24 hours'),
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (id, user_id)
);
CREATE UNIQUE INDEX account_recovery_one_active ON account_recovery_operations(user_id) WHERE state IN (1, 2);
CREATE INDEX account_recovery_expiry ON account_recovery_operations(expires_at, id) WHERE state IN (1,2);
CREATE INDEX account_recovery_retention ON account_recovery_operations(updated_at, id) WHERE state NOT IN (1,2);
ALTER TABLE users ADD CONSTRAINT users_active_recovery_owner
    FOREIGN KEY (active_recovery_id, id) REFERENCES account_recovery_operations(id, user_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE account_recovery_receipts (
    operation_id UUID NOT NULL REFERENCES account_recovery_operations(id) ON DELETE CASCADE,
    mutation_id UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest) = 32),
    revision BIGINT NOT NULL CHECK (revision > 0),
    state SMALLINT NOT NULL CHECK (state BETWEEN 1 AND 6),
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (operation_id, mutation_id)
);
CREATE TABLE account_recovery_quota (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    active_count INTEGER NOT NULL CHECK (active_count BETWEEN 0 AND 1024),
    retained_count INTEGER NOT NULL CHECK (retained_count BETWEEN active_count AND 8192)
);
INSERT INTO account_recovery_quota VALUES (TRUE, 0, 0);
