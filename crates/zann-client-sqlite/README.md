# zann-client-sqlite

Production SQLite implementation of the canonical `zann-client` sync
persistence port under one exact, authorized Config v2 generation.

It materializes only absent exact remote storage/catalog rows, publishes an
initial personal-vault key with initialize-once server semantics, and commits
push/pull changes transactionally. It never replaces an existing binding.

`SqliteSyncStoreFactory` implements the DB-free `AppSyncStoreFactory` port for
one exact, already-existing native database location. Its explicit constructor
prevalidates that filesystem location; the operation method performs no I/O
before its returned future is polled, performs no network or config lookup,
and delegates to the same pinned, non-creating `SqliteSyncStore::open`
boundary. COSMIC and FFI use this factory through `AppClient`.

The generic `zann-db` projection-reset primitive is outside this adapter's
current contract. `reset_projection_if_clean` returns `Unavailable` before any
database access; reset/FTS cleanup hardening is deferred with reset
activation.

End-to-end coverage exercises validated catalog, push and pull models without
widening their public construction surface.

## Current schema boundary

The current SQLite schema identifies vaults and items with globally unique UUID
primary keys rather than composite `(storage_id, id)` keys. Consequently this
adapter accepts exactly one configured connection, one profile for that
connection, and one remote storage row. Simultaneous endpoint/profile caches
remain disabled until the schema and activation saga are redesigned.

Every adapter instance is an operation-scoped lease over one explicit
`SessionTarget`, one explicit `ClientPaths`, one pinned SQLite database, and one
immutable master key. Construction opens only an absolute, normalized,
already-existing regular database file and never reads config or creates a
missing file. `resolve_target` installs one opaque
`AuthorizedTargetGeneration`; a second different authorization fails closed.
The adapter never consults `HOME`, constructs a SQLite URI from a displayed
path, or keeps a mutable target/key side map.

Catalog and pull mutations acquire the async Config v2 sync-commit lease in
the canonical `SyncCommit -> Config` order. While that lease remains held, the
adapter rechecks the pinned physical and logical database identity and calls a
`BEGIN IMMEDIATE` DB API with an exact repository fingerprint, stable-target
fingerprint, unsigned config revision, and config-content fingerprint. The DB
rejects rollback, cross-repository/target reuse, corrupt or partial generation
rows, and an equal revision with different content. A newer revision advances
atomically with the catalog or pull transaction. Only exact catalog reconcile
may make the first generation claim, and only when all target key fingerprints
are `NULL` and item, history, pending, cursor, and cross-storage references are
empty. Pull refuses an unclaimed storage.

The adapter dispatches each catalog or pull mutation synchronously into an
owned Tokio terminal task before returning its outer future. A synchronous,
process-wide single-flight permit admits at most one queued or running catalog
or pull payload across all adapter instances; a second mutation returns `Busy`
without spawning or polling its payload. Dropping or cancelling the admitted
outer future detaches the join handle but cannot release the permit or
generation lease while SQLite `COMMIT` is still in flight. Any task failure is
reported as `CommitOutcomeUnknown` when the returned future is still observed;
if no Tokio runtime is active, the adapter returns `Unavailable` before
starting a mutation. Runtime or process shutdown can still prevent delivery of
the live result, so restart recovery must read the durable generation and
checkpoint rather than blindly replaying a write.

The existing-file factory canonicalizes the private parent, rejects symlinks,
non-regular files and, on Unix, hard links, checks SQLite `-wal`, `-shm`, and
`-journal` sidecars before WAL opens, tightens files to mode `0600`, and uses an
eager pool capped at one connection. It pins filesystem identity and a random
logical database UUID across the open and before/after leased writes. SQLx
does not expose an atomic no-follow "open this inode" primitive, so these
checks are not a sandbox against a malicious same-UID process that swaps an
exact clone (including the logical UUID) during the remaining open race; the
state directory must remain private.
