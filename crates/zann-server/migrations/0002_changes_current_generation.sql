-- A sync cursor is only safe when every current item generation is represented
-- exactly once in the append-only changes stream.

-- Operational note: this unreleased migration performs full-table validation,
-- deduplication and backfill while holding write locks on the sync tables.
-- Run it in a maintenance window, budget temporary space for the unique index,
-- and set deployment-level lock/statement timeouts appropriate to the dataset.
-- The lock is intentionally held through trigger installation so no writer can
-- slip between validation, backfill and enforcement. Reads may continue.
LOCK TABLE vaults, items, item_history, attachments, changes IN SHARE ROW EXCLUSIVE MODE;

-- Keep the database contract byte-for-byte compatible with the clients and
-- HTTP handlers. octet_length is intentional: wire limits are UTF-8 bytes, not
-- Unicode scalar counts.
CREATE FUNCTION is_item_trim_whitespace(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT candidate IN (
        chr(9), chr(10), chr(11), chr(12), chr(13), chr(32), chr(133),
        chr(160), chr(5760), chr(8192), chr(8193), chr(8194), chr(8195),
        chr(8196), chr(8197), chr(8198), chr(8199), chr(8200), chr(8201),
        chr(8202), chr(8232), chr(8233), chr(8239), chr(8287), chr(12288)
    );
$$;

CREATE FUNCTION is_canonical_item_path(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT octet_length(candidate) BETWEEN 1 AND 500
       AND NOT is_item_trim_whitespace(left(candidate, 1))
       AND NOT is_item_trim_whitespace(right(candidate, 1))
       AND cardinality(string_to_array(candidate, '/')) BETWEEN 1 AND 32
       AND NOT EXISTS (
            SELECT 1
            FROM unnest(string_to_array(candidate, '/')) AS path_segment(segment)
            WHERE segment = ''
               OR octet_length(segment) > 200
               OR segment IN ('.', '..')
               OR left(segment, 1) = '.'
               OR is_item_trim_whitespace(left(segment, 1))
               OR is_item_trim_whitespace(right(segment, 1))
       );
$$;

CREATE FUNCTION canonical_item_basename(candidate TEXT)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT split_part(
        candidate,
        '/',
        GREATEST(cardinality(string_to_array(candidate, '/')), 1)
    );
$$;

CREATE FUNCTION is_canonical_item_type(candidate TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT octet_length(candidate) BETWEEN 1 AND 128
       AND NOT is_item_trim_whitespace(left(candidate, 1))
       AND NOT is_item_trim_whitespace(right(candidate, 1));
$$;

-- The legacy secrets API stored item paths with a leading route slash even
-- though every other item writer uses slashless storage paths. Normalize only
-- that precisely understood legacy shape. Ambiguous, multiply-prefixed, or
-- otherwise non-canonical paths remain fail-closed in the general preflight.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM (
            SELECT
                vault_id,
                CASE
                    WHEN type_id = 'secret'
                     AND path LIKE '/%'
                     AND path NOT LIKE '//%'
                     AND is_canonical_item_path(substring(path FROM 2))
                    THEN substring(path FROM 2)
                    ELSE path
                END AS normalized_path
            FROM items
        ) AS normalized
        GROUP BY vault_id, normalized_path
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            CONSTRAINT = 'items_secret_path_normalization_collision',
            MESSAGE = 'legacy secret path normalization would collide with an existing item';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items
        WHERE type_id = 'secret'
          AND path LIKE '/%'
          AND path NOT LIKE '//%'
          AND is_canonical_item_path(substring(path FROM 2))
          AND (version = 9223372036854775807 OR row_version = 9223372036854775807)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22003',
            CONSTRAINT = 'items_secret_path_normalization_version',
            MESSAGE = 'legacy secret path normalization cannot advance item version';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items AS item
        JOIN changes AS change
          ON change.item_id = item.id
         AND change.version = item.version + 1
        WHERE item.type_id = 'secret'
          AND item.path LIKE '/%'
          AND item.path NOT LIKE '//%'
          AND is_canonical_item_path(substring(item.path FROM 2))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_secret_path_normalization_generation',
            MESSAGE = 'legacy secret path normalization generation already exists';
    END IF;

    UPDATE items
    SET path = substring(path FROM 2),
        name = canonical_item_basename(substring(path FROM 2)),
        version = version + 1,
        row_version = row_version + 1,
        updated_at = GREATEST(
            transaction_timestamp(),
            updated_at + INTERVAL '1 microsecond'
        )
    WHERE type_id = 'secret'
      AND path LIKE '/%'
      AND path NOT LIKE '//%'
      AND is_canonical_item_path(substring(path FROM 2));
END;
$$;

-- Validate every remaining legacy row before deduplication or sequence work.
-- The fixed check order makes a dirty installation fail with a deterministic
-- constraint name; the path normalization above is transactional and therefore
-- rolls back with any later failed preflight.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM items WHERE NOT is_canonical_item_path(path)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_path_canonical',
            MESSAGE = 'legacy item path violates the canonical contract';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items
        WHERE octet_length(name) NOT BETWEEN 1 AND 200
           OR name IS DISTINCT FROM canonical_item_basename(path)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_name_matches_path',
            MESSAGE = 'legacy item name disagrees with its canonical path';
    END IF;

    IF EXISTS (
        SELECT 1 FROM items WHERE NOT is_canonical_item_type(type_id)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_type_id_canonical',
            MESSAGE = 'legacy item type_id violates the canonical contract';
    END IF;

    IF EXISTS (
        SELECT 1 FROM items WHERE version < 1 OR row_version < 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_generation_positive',
            MESSAGE = 'legacy item generation counters must be positive';
    END IF;

    IF EXISTS (
        SELECT 1 FROM item_history WHERE version < 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'item_history_version_positive',
            MESSAGE = 'legacy item history version must be positive';
    END IF;

    IF EXISTS (
        SELECT 1 FROM changes WHERE version < 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_version_positive',
            MESSAGE = 'legacy change version must be positive';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items
        WHERE octet_length(payload_enc) NOT BETWEEN 1 AND 262400
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_payload_bounds',
            MESSAGE = 'legacy item ciphertext violates the bounded contract';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items
        WHERE octet_length(checksum) <> 64
           OR checksum ~ '[^0-9a-f]'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_checksum_format',
            MESSAGE = 'legacy item checksum is not lowercase BLAKE3 hex';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items
        WHERE tags IS NOT NULL AND octet_length(tags::text) > 65536
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_tags_storage_bounds',
            MESSAGE = 'legacy item tags exceed the sync metadata bound';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM item_history
        WHERE octet_length(payload_enc) NOT BETWEEN 1 AND 262400
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'item_history_payload_bounds',
            MESSAGE = 'legacy item history ciphertext violates the bounded contract';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM item_history
        WHERE octet_length(checksum) <> 64
           OR checksum ~ '[^0-9a-f]'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'item_history_checksum_format',
            MESSAGE = 'legacy item history checksum is not lowercase BLAKE3 hex';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM item_history
        WHERE octet_length(changed_by_email) NOT BETWEEN 1 AND 320
           OR (
                changed_by_name IS NOT NULL
                AND octet_length(changed_by_name) > 200
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'item_history_actor_metadata_bounds',
            MESSAGE = 'legacy item history actor metadata exceeds sync bounds';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM item_history
        WHERE (fields_changed IS NOT NULL AND octet_length(fields_changed::text) > 65536)
           OR (
                changed_by_device_name IS NOT NULL
                AND octet_length(changed_by_device_name) > 200
              )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'item_history_aux_metadata_bounds',
            MESSAGE = 'legacy item history auxiliary metadata exceeds bounds';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM attachments
        WHERE octet_length(filename) NOT BETWEEN 1 AND 255
           OR octet_length(mime_type) NOT BETWEEN 1 AND 255
           OR enc_mode NOT IN ('plain', 'opaque')
           OR octet_length(content_enc) NOT BETWEEN 1 AND 10486784
           OR octet_length(checksum) <> 64
           OR checksum ~ '[^0-9a-f]'
           OR (storage_url IS NOT NULL AND octet_length(storage_url) > 2048)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'attachments_bounded_contract',
            MESSAGE = 'legacy attachment violates the bounded contract';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM items
        WHERE (rotation_candidate_enc IS NOT NULL AND octet_length(rotation_candidate_enc) > 65536)
           OR (rotation_state IS NOT NULL AND octet_length(rotation_state) > 32)
           OR (rotation_aborted_reason IS NOT NULL AND octet_length(rotation_aborted_reason) > 1024)
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'items_rotation_metadata_bounds',
            MESSAGE = 'legacy item rotation metadata exceeds bounds';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM vaults
        WHERE octet_length(slug) NOT BETWEEN 1 AND 128
           OR slug <> btrim(slug)
           OR slug ~ '[^A-Za-z0-9_-]'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'vaults_slug_canonical',
            MESSAGE = 'legacy vault slug violates the canonical catalog contract';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM vaults
        WHERE octet_length(name) NOT BETWEEN 1 AND 200
           OR name <> btrim(name)
           OR name ~ '^[[:space:]]'
           OR name ~ '[[:space:]]$'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'vaults_name_canonical',
            MESSAGE = 'legacy vault name violates the canonical catalog contract';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM vaults
        WHERE octet_length(vault_key_enc) NOT BETWEEN 1 AND 65536
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'vaults_key_bounds',
            MESSAGE = 'legacy vault key ciphertext violates the bounded contract';
    END IF;

    IF EXISTS (
        SELECT 1 FROM vaults WHERE octet_length(tags::text) > 65536
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'vaults_tags_storage_bounds',
            MESSAGE = 'legacy vault tags exceed the sync metadata bound';
    END IF;
END;
$$;

-- A duplicate generation is safe to collapse only when every row describes
-- one semantic event. Grouping avoids a quadratic self-join on dirty tables.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM changes
        GROUP BY item_id, version
        HAVING COUNT(*) > 1
           AND COUNT(DISTINCT ROW(vault_id, op, device_id, created_at)) > 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_generation_semantics',
            MESSAGE = 'conflicting duplicate change generations';
    END IF;
END;
$$;

-- Even historical generations must belong to the same vault as their item.
-- Otherwise a change cursor for one vault can expose another vault's row.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM changes AS change
        JOIN items AS item ON item.id = change.item_id
        WHERE change.vault_id IS DISTINCT FROM item.vault_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_item_vault_matches',
            MESSAGE = 'change vault_id disagrees with its item';
    END IF;
END;
$$;

-- Existing current generations must agree with the authoritative item row.
-- Abort instead of rewriting an event that clients may already have observed.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM items AS item
        JOIN changes AS change
          ON change.item_id = item.id
         AND change.version = item.version
        WHERE change.vault_id IS DISTINCT FROM item.vault_id
           OR change.op IS DISTINCT FROM (CASE
                WHEN item.deleted_at IS NOT NULL THEN 3
                WHEN item.version = 1 THEN 1
                ELSE 2
              END)::SMALLINT
           OR change.device_id IS DISTINCT FROM item.device_id
           OR change.created_at IS DISTINCT FROM item.updated_at
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_current_generation_matches_item',
            MESSAGE = 'current change generation disagrees with item state';
    END IF;
END;
$$;

-- Explicit sequence values may have been imported by older installations, and
-- deleting a duplicate below must never make a previously issued cursor
-- reusable. All rejecting preflight checks above run before this non-
-- transactional sequence operation.
SELECT setval(
    pg_get_serial_sequence('changes', 'seq'),
    GREATEST(
        COALESCE(MAX(seq), 1),
        (SELECT last_value FROM changes_seq_seq)
    ),
    CASE
        WHEN MAX(seq) IS NOT NULL THEN TRUE
        ELSE (SELECT is_called FROM changes_seq_seq)
    END
)
FROM changes;

-- Keep the earliest sequence for proven-equivalent legacy duplicates. This
-- preserves the first point at which that semantic generation became visible.
WITH duplicate_generations AS (
    SELECT
        seq,
        ROW_NUMBER() OVER (
            PARTITION BY item_id, version
            ORDER BY seq ASC
        ) AS duplicate_rank
    FROM changes
)
DELETE FROM changes AS change
USING duplicate_generations AS duplicate
WHERE change.seq = duplicate.seq
  AND duplicate.duplicate_rank > 1;

CREATE UNIQUE INDEX idx_changes_item_version
    ON changes(item_id, version);

ALTER TABLE items
    ADD CONSTRAINT items_path_canonical
        CHECK (is_canonical_item_path(path)),
    ADD CONSTRAINT items_name_matches_path
        CHECK (
            octet_length(name) BETWEEN 1 AND 200
            AND name = canonical_item_basename(path)
        ),
    ADD CONSTRAINT items_type_id_canonical
        CHECK (is_canonical_item_type(type_id)),
    ADD CONSTRAINT items_generation_positive
        CHECK (version >= 1 AND row_version >= 1),
    ADD CONSTRAINT items_payload_bounds
        CHECK (octet_length(payload_enc) BETWEEN 1 AND 262400),
    ADD CONSTRAINT items_checksum_format
        CHECK (octet_length(checksum) = 64 AND checksum !~ '[^0-9a-f]'),
    ADD CONSTRAINT items_tags_storage_bounds
        CHECK (tags IS NULL OR octet_length(tags::text) <= 65536),
    ADD CONSTRAINT items_rotation_metadata_bounds
        CHECK (
            (rotation_candidate_enc IS NULL OR octet_length(rotation_candidate_enc) <= 65536)
            AND (rotation_state IS NULL OR octet_length(rotation_state) <= 32)
            AND (
                rotation_aborted_reason IS NULL
                OR octet_length(rotation_aborted_reason) <= 1024
            )
        );

ALTER TABLE item_history
    ADD CONSTRAINT item_history_version_positive
        CHECK (version >= 1),
    ADD CONSTRAINT item_history_payload_bounds
        CHECK (octet_length(payload_enc) BETWEEN 1 AND 262400),
    ADD CONSTRAINT item_history_checksum_format
        CHECK (octet_length(checksum) = 64 AND checksum !~ '[^0-9a-f]'),
    ADD CONSTRAINT item_history_actor_metadata_bounds
        CHECK (
            octet_length(changed_by_email) BETWEEN 1 AND 320
            AND (
                changed_by_name IS NULL
                OR octet_length(changed_by_name) <= 200
            )
        ),
    ADD CONSTRAINT item_history_aux_metadata_bounds
        CHECK (
            (fields_changed IS NULL OR octet_length(fields_changed::text) <= 65536)
            AND (
                changed_by_device_name IS NULL
                OR octet_length(changed_by_device_name) <= 200
            )
        );

ALTER TABLE attachments
    ADD CONSTRAINT attachments_bounded_contract
        CHECK (
            octet_length(filename) BETWEEN 1 AND 255
            AND octet_length(mime_type) BETWEEN 1 AND 255
            AND enc_mode IN ('plain', 'opaque')
            AND octet_length(content_enc) BETWEEN 1 AND 10486784
            AND octet_length(checksum) = 64
            AND checksum !~ '[^0-9a-f]'
            AND (storage_url IS NULL OR octet_length(storage_url) <= 2048)
        );

ALTER TABLE changes
    ADD CONSTRAINT changes_version_positive
        CHECK (version >= 1);

ALTER TABLE vaults
    ADD CONSTRAINT vaults_slug_canonical
        CHECK (
            octet_length(slug) BETWEEN 1 AND 128
            AND slug = btrim(slug)
            AND slug !~ '[^A-Za-z0-9_-]'
        ),
    ADD CONSTRAINT vaults_name_canonical
        CHECK (
            octet_length(name) BETWEEN 1 AND 200
            AND name = btrim(name)
            AND name !~ '^[[:space:]]'
            AND name !~ '[[:space:]]$'
        ),
    ADD CONSTRAINT vaults_key_bounds
        CHECK (octet_length(vault_key_enc) BETWEEN 1 AND 65536),
    ADD CONSTRAINT vaults_tags_storage_bounds
        CHECK (octet_length(tags::text) <= 65536);

-- Backfill only the current generation. Older generations that were never in
-- the stream cannot be reconstructed reliably, while the current row contains
-- all provenance needed by pull: its actor device, version, timestamp and
-- tombstone state. Ordering makes sequence assignment reproducible.
INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
SELECT
    item.vault_id,
    item.id,
    CASE
        WHEN item.deleted_at IS NOT NULL THEN 3
        WHEN item.version = 1 THEN 1
        ELSE 2
    END,
    item.version,
    item.device_id,
    item.updated_at
FROM items AS item
WHERE NOT EXISTS (
    SELECT 1
    FROM changes AS change
    WHERE change.item_id = item.id
      AND change.version = item.version
)
ORDER BY item.updated_at ASC, item.id ASC
ON CONFLICT (item_id, version) DO NOTHING;

-- BIGSERIAL allocation is not transactional: a lower sequence can remain
-- uncommitted while a higher sequence commits, allowing a pull cursor to skip
-- the late commit. Seed a singleton transactional clock after backfill from
-- both the visible rows and the preserved legacy sequence high-water mark.
CREATE TABLE changes_commit_clock (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_seq BIGINT NOT NULL CHECK (last_seq >= 0)
);

INSERT INTO changes_commit_clock (singleton, last_seq)
SELECT
    TRUE,
    GREATEST(
        COALESCE(MAX(seq), 0),
        (SELECT last_value FROM changes_seq_seq)
    )
FROM changes;

ALTER TABLE changes ALTER COLUMN seq DROP DEFAULT;

-- Change rows are append-only semantic generations. An exact no-op UPDATE is
-- permitted for idempotent retry machinery, but inserts must describe the
-- item's current generation exactly and must never cross vault boundaries.
CREATE FUNCTION validate_change_generation_semantics()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    item_vault_id UUID;
    item_version BIGINT;
    item_deleted_at TIMESTAMPTZ;
    item_device_id UUID;
    item_updated_at TIMESTAMPTZ;
    expected_op SMALLINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Foreign-key cascades from the owning item/vault run nested inside the
        -- referential-action trigger and must remain possible. A direct delete
        -- would remove the sole current generation and is rejected.
        IF pg_trigger_depth() > 1 THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_generation_delete_forbidden',
            MESSAGE = 'change generations may only be deleted by parent cascade';
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF (
            NEW.seq,
            NEW.vault_id,
            NEW.item_id,
            NEW.op,
            NEW.version,
            NEW.device_id,
            NEW.created_at
        ) IS DISTINCT FROM (
            OLD.seq,
            OLD.vault_id,
            OLD.item_id,
            OLD.op,
            OLD.version,
            OLD.device_id,
            OLD.created_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'changes_generation_immutable',
                MESSAGE = 'change generations are immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM changes AS existing
        WHERE existing.item_id = NEW.item_id
          AND existing.version = NEW.version
    ) THEN
        IF NOT EXISTS (
            SELECT 1
            FROM changes AS existing
            WHERE existing.item_id = NEW.item_id
              AND existing.version = NEW.version
              AND existing.vault_id IS NOT DISTINCT FROM NEW.vault_id
              AND existing.op IS NOT DISTINCT FROM NEW.op
              AND existing.device_id IS NOT DISTINCT FROM NEW.device_id
              AND existing.created_at IS NOT DISTINCT FROM NEW.created_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'changes_generation_semantics',
                MESSAGE = 'change generation conflicts with existing semantics';
        END IF;
        RETURN NEW;
    END IF;

    SELECT
        item.vault_id,
        item.version,
        item.deleted_at,
        item.device_id,
        item.updated_at
    INTO
        item_vault_id,
        item_version,
        item_deleted_at,
        item_device_id,
        item_updated_at
    FROM items AS item
    WHERE item.id = NEW.item_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            CONSTRAINT = 'changes_item_id_fkey',
            MESSAGE = 'change item does not exist';
    END IF;

    IF NEW.vault_id IS DISTINCT FROM item_vault_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_item_vault_matches',
            MESSAGE = 'change vault_id disagrees with its item';
    END IF;

    IF item_deleted_at IS NOT NULL THEN
        expected_op := 3;
    ELSIF item_version = 1 THEN
        expected_op := 1;
    ELSE
        expected_op := 2;
    END IF;

    IF NEW.version IS DISTINCT FROM item_version
        OR NEW.op IS DISTINCT FROM expected_op
        OR NEW.device_id IS DISTINCT FROM item_device_id
        OR NEW.created_at IS DISTINCT FROM item_updated_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_current_generation_matches_item',
            MESSAGE = 'change generation disagrees with current item state';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER changes_10_validate_semantics
BEFORE INSERT OR UPDATE OR DELETE ON changes
FOR EACH ROW
EXECUTE FUNCTION validate_change_generation_semantics();

-- Updating the singleton row serializes allocation until transaction end. A
-- rollback restores the clock value, so only an invisible sequence is reused,
-- and no transaction can commit a higher sequence before a lower one.
CREATE FUNCTION assign_change_commit_sequence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- An exact retry was already approved by the semantic trigger. Reuse the
    -- existing value for conflict handling without advancing the clock.
    SELECT existing.seq
    INTO NEW.seq
    FROM changes AS existing
    WHERE existing.item_id = NEW.item_id
      AND existing.version = NEW.version;

    IF FOUND THEN
        RETURN NEW;
    END IF;

    UPDATE changes_commit_clock
    SET last_seq = last_seq + 1
    WHERE singleton
    RETURNING last_seq INTO NEW.seq;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'changes_commit_clock_singleton',
            MESSAGE = 'change commit clock is missing';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER changes_20_assign_commit_sequence
BEFORE INSERT ON changes
FOR EACH ROW
EXECUTE FUNCTION assign_change_commit_sequence();

-- ItemRepo writes and the sync push path normally append their own change row.
-- This deferred constraint trigger is the database-level safety net for writers
-- such as server-side key rotation that advance an item version directly. When
-- an explicit change is inserted in the same transaction, the trigger observes
-- it at commit and does nothing.
CREATE FUNCTION ensure_current_item_change_generation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    change_op SMALLINT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Moving an item would make its historical changes join against and
        -- expose the new vault's current row under the old vault cursor.
        IF NEW.vault_id IS DISTINCT FROM OLD.vault_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'items_vault_immutable',
                MESSAGE = 'item vault_id is immutable';
        END IF;

        -- Item history has no historical type_id column. Allowing a type
        -- conversion would make every prior typed payload undecodable against
        -- the current item metadata, so type changes remain fail-closed until
        -- the history schema can carry that provenance.
        IF NEW.type_id IS DISTINCT FROM OLD.type_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'items_type_immutable',
                MESSAGE = 'item type_id is immutable';
        END IF;

        IF NEW.version < OLD.version THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'items_version_monotonic',
                MESSAGE = 'item version cannot decrease';
        END IF;

        IF NEW.version = OLD.version THEN
            IF NEW.sync_status IS DISTINCT FROM OLD.sync_status
                OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
                OR NEW.deleted_by_user_id IS DISTINCT FROM OLD.deleted_by_user_id
                OR NEW.deleted_by_device_id IS DISTINCT FROM OLD.deleted_by_device_id
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    CONSTRAINT = 'items_deletion_requires_version',
                    MESSAGE = 'item deletion state requires a version advance';
            END IF;

            IF NEW.path IS DISTINCT FROM OLD.path
                OR NEW.name IS DISTINCT FROM OLD.name
                OR NEW.type_id IS DISTINCT FROM OLD.type_id
                OR NEW.payload_enc IS DISTINCT FROM OLD.payload_enc
                OR NEW.checksum IS DISTINCT FROM OLD.checksum
                OR NEW.device_id IS DISTINCT FROM OLD.device_id
                OR NEW.updated_at IS DISTINCT FROM OLD.updated_at
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    CONSTRAINT = 'items_sync_fields_require_version',
                    MESSAGE = 'sync-visible item fields require a version advance';
            END IF;
            RETURN NULL;
        END IF;
    END IF;

    IF NEW.deleted_at IS NOT NULL THEN
        change_op := 3;
    ELSIF TG_OP = 'INSERT' AND NEW.version = 1 THEN
        change_op := 1;
    ELSE
        change_op := 2;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM changes AS existing
        WHERE existing.item_id = NEW.id
          AND existing.version = NEW.version
    ) THEN
        IF NOT EXISTS (
            SELECT 1
            FROM changes AS existing
            WHERE existing.item_id = NEW.id
              AND existing.version = NEW.version
              AND existing.vault_id IS NOT DISTINCT FROM NEW.vault_id
              AND existing.op IS NOT DISTINCT FROM change_op
              AND existing.device_id IS NOT DISTINCT FROM NEW.device_id
              AND existing.created_at IS NOT DISTINCT FROM NEW.updated_at
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'changes_current_generation_matches_item',
                MESSAGE = 'change generation conflicts with current item state';
        END IF;
        RETURN NULL;
    END IF;

    INSERT INTO changes (vault_id, item_id, op, version, device_id, created_at)
    VALUES (
        NEW.vault_id,
        NEW.id,
        change_op,
        NEW.version,
        NEW.device_id,
        NEW.updated_at
    );

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER ensure_current_item_change_generation
AFTER INSERT OR UPDATE ON items
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION ensure_current_item_change_generation();
