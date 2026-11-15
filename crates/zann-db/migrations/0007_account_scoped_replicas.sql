-- Endpoint trust belongs to Config; local replicas are distinct per account.
-- The preceding unique URL index guaranteed that no old row can conflict here.
DROP INDEX idx_storages_server_url;
CREATE INDEX idx_storages_server_url ON storages(server_url)
    WHERE server_url IS NOT NULL;
CREATE UNIQUE INDEX idx_storages_server_account ON storages(server_url, account_subject)
    WHERE kind = 2 AND server_url IS NOT NULL AND account_subject IS NOT NULL;
