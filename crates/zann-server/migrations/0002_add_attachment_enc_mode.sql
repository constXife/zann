ALTER TABLE attachments
ADD COLUMN enc_mode TEXT NOT NULL DEFAULT 'plain';
