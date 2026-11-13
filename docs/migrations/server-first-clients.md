# Server-first client cutover (#241)

Native Zann clients now cache server vaults. A new device connects to a server,
signs in or registers, enters its master password, and completes a first sync.
The account's KDF identity is stored in Config v2; the client never mints a
standalone identity or creates a fallback personal vault.

## Existing databases

SQLite migration `0004_server_replicas.sql` runs in one transaction. It removes
empty legacy Local storage rows, including the old nil UUID seed. It keeps
server caches. Existing migration files and their checksums are unchanged.

If any legacy local storage has vaults, items, history or pending changes, the
migration fails with `legacy_local_data_requires_export` and leaves the data
intact. Before upgrading, use the older client to export that vault and keep an
encrypted database snapshot. Set up a fresh client root against the desired
server, sync it, and import the export into an explicitly selected server
storage. Keep the old data until the imported items have been verified. Do not
change storage kinds or KDF salts in SQLite/JSON by hand.

A previously synced server replica still unlocks, reads, searches, edits,
exports, snapshots and verifies offline. Unsent changes stay pending. Forgetting
the connection does not erase its cache; reconnect to the same account/server
to resume syncing. Plain backup import requires an explicit server destination;
Apple Passwords CSV import targets an existing synced personal vault.

## Test and development fixtures

`zann-client-sqlite/test-support` exposes `LocalVault::seed_offline_fixture`.
It requires an empty client root and seeds a synthetic remote storage, account
KDF identity and encrypted personal vault key without contacting a server.
The fixture is disconnected: edits create pending changes as production does.

Rust integration tests and the COSMIC demo example opt in explicitly. The Apple
debug xcframework enables `zann-ffi/test-support`, exposing `seedOfflineFixture`
to Swift tests. Release builds omit it. Server login/first-sync tests continue
to exercise real authentication rather than fixture initialization.
