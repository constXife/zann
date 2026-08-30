-- Keep ordinary item type changes fail-closed while allowing the privileged
-- provisioning repair command to migrate one explicitly identified legacy
-- item. The three transaction-local settings must match the row transition
-- exactly; they disappear automatically at transaction end.
CREATE OR REPLACE FUNCTION ensure_current_item_change_generation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    change_op SMALLINT;
    authorized_retype BOOLEAN;
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

        authorized_retype :=
            current_setting('zann.retype_item_id', true) = OLD.id::TEXT
            AND current_setting('zann.retype_from_type_id', true) = OLD.type_id
            AND current_setting('zann.retype_to_type_id', true) = NEW.type_id;

        -- Item history has no separate historical type_id column. Type changes
        -- therefore remain fail-closed unless the provisioning command scopes
        -- this transaction to the exact item and transition after rewriting
        -- every retained encrypted history payload.
        IF NEW.type_id IS DISTINCT FROM OLD.type_id
            AND NOT COALESCE(authorized_retype, FALSE)
        THEN
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
