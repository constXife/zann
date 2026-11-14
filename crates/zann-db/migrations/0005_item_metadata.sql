-- NULL means attributes that the older replica never captured. Never invent
-- empty attributes for those rows: sync/export require a fresh authoritative pull.
ALTER TABLE items_cache ADD COLUMN metadata TEXT;
ALTER TABLE pending_changes ADD COLUMN metadata TEXT;
