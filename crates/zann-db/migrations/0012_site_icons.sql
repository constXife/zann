CREATE TABLE site_icons (
    storage_id BLOB NOT NULL,
    vault_id BLOB NOT NULL,
    host_tag TEXT NOT NULL,
    pixels_enc BLOB NOT NULL CHECK (length(pixels_enc) BETWEEN 1024 AND 1280),
    PRIMARY KEY (storage_id, vault_id, host_tag),
    FOREIGN KEY (storage_id, vault_id) REFERENCES local_vaults(storage_id, id) ON DELETE CASCADE
);
