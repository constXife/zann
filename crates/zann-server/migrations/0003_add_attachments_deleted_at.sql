ALTER TABLE attachments
ADD COLUMN deleted_at TIMESTAMPTZ;

CREATE INDEX idx_attachments_deleted_at ON attachments(deleted_at);
