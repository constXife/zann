ALTER TABLE users ADD COLUMN account_key_descriptor BYTEA CHECK (octet_length(account_key_descriptor) <= 1024);
CREATE TABLE account_credential_fence (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    generation BIGINT NOT NULL CHECK (generation>0)
);
INSERT INTO account_credential_fence VALUES (TRUE,1);
CREATE TABLE account_passkeys (
    credential_id BYTEA PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    user_id UUID NOT NULL REFERENCES users(id),
    name TEXT NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    mode SMALLINT NOT NULL CHECK (mode IN (1,2)),
    credential BYTEA NOT NULL CHECK (octet_length(credential) BETWEEN 1 AND 8192),
    key_grant BYTEA CHECK (octet_length(key_grant) <= 4096),
    auth_epoch BIGINT NOT NULL CHECK (auth_epoch > 0),
    creation_generation BIGINT NOT NULL CHECK (creation_generation>0),
    revoked_at TIMESTAMPTZ,
    session_epoch BIGINT NOT NULL DEFAULT 1 CHECK (session_epoch > 0),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((mode = 2) = (key_grant IS NOT NULL))
);
CREATE INDEX account_passkeys_user ON account_passkeys(user_id, credential_id) WHERE revoked_at IS NULL;
ALTER TABLE sessions
    ADD COLUMN passkey_credential_id BYTEA REFERENCES account_passkeys(credential_id),
    ADD COLUMN passkey_session_epoch BIGINT,
    ADD CONSTRAINT sessions_passkey_epoch_pair CHECK ((passkey_credential_id IS NULL) = (passkey_session_epoch IS NULL));
CREATE INDEX sessions_passkey ON sessions(passkey_credential_id) WHERE passkey_credential_id IS NOT NULL;

-- A fixed-capacity server challenge/candidate store: no anonymous row growth,
-- global allocation counter or cross-replica in-memory challenge authority.
CREATE TABLE account_access_slots (
    slot INTEGER PRIMARY KEY CHECK (slot BETWEEN 1 AND 8192),
    operation_id UUID UNIQUE,
    user_id UUID REFERENCES users(id),
    authority_kind SMALLINT CHECK (authority_kind IN (1,2,3)),
    authority_id UUID,
    auth_epoch BIGINT,
    security_revision BIGINT,
    request_digest BYTEA CHECK (octet_length(request_digest) = 32),
    payload BYTEA CHECK (octet_length(payload) <= 65536),
    revision BIGINT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity',
    CHECK ((operation_id IS NULL) = (payload IS NULL))
);
INSERT INTO account_access_slots (slot) SELECT generate_series(1,8192);
CREATE INDEX account_access_slot_expiry ON account_access_slots(expires_at,slot);
CREATE INDEX account_access_slot_user ON account_access_slots(user_id,expires_at);

CREATE TABLE account_custody_nonces (
    user_id UUID NOT NULL REFERENCES users(id),
    authority_id UUID NOT NULL,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    purpose TEXT NOT NULL CHECK (purpose IN ('grant_add','grant_replace','grant_remove','code_rotate','credential_add','credential_revoke','credential_mode')),
    body_digest BYTEA NOT NULL CHECK (octet_length(body_digest) = 32),
    security_revision BIGINT NOT NULL CHECK (security_revision > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id)
);

ALTER TABLE users ADD COLUMN recovery_candidate_id UUID;
CREATE TABLE account_security_receipts (
    user_id UUID NOT NULL REFERENCES users(id),
    mutation_id UUID NOT NULL,
    request_digest BYTEA NOT NULL CHECK (octet_length(request_digest)=32),
    reply BYTEA NOT NULL CHECK (octet_length(reply)<=2048),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id,mutation_id)
);
CREATE INDEX account_security_receipt_expiry ON account_security_receipts(user_id,committed_at);

ALTER TABLE account_recovery_receipts ADD COLUMN reply BYTEA CHECK (octet_length(reply)<=3072);
