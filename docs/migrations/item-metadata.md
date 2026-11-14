# Item metadata and server backup import cutover

This Pre-GA change requires updating the server and native clients together.
Item sync now carries `tags` and `favorite`; the old wire shape is not retained.
Cryptographic envelopes, KDF parameters and payload serialization are unchanged.

SQLite migration 0005 adds nullable item/pending metadata. NULL means that an
older replica never captured the authoritative server attributes. It is not
an empty tag list or `favorite = false`. Existing ciphertext and pending rows
remain intact and can still be read offline. Publishing an unknown pending
attribute set fails with `sync_metadata_refresh_required`; exporting unknown
attributes fails with `backup_metadata_refresh_required`.

Before upgrading, synchronize outstanding edits with the matching older
server/client versions and retain an owner-only snapshot or plain export.
After updating both sides, a clean replica may be explicitly reset and fully
synced. The reset refuses unsent/dirty state or non-server history; it never
discards such data automatically. If reset is refused, keep the original root
and its exports, open a new client root, sign into the same account and sync.
Review and transfer any outstanding edits before deleting the original root.
Do not replace NULL attributes with empty values to bypass these checks.

Plain backup v1 now preserves tags and favorite. Older v1 files that never
contained those fields import them as absent tags/false, as specified by #243;
attributes missing from those old files cannot be reconstructed offline.
Import uses an explicitly selected destination server storage. Personal data
is encrypted locally for that account's personal vault; shared data follows
the shared server-encryption plane. Shared vault identity uses the original
UUID or `import-<UUID>` slug, so equal display names do not merge vaults.

Files are streamed with bounded queues and a 50 MiB import ceiling. Vault
count follows the canonical sync catalog limit. Existing item paths and deleted
records are counted as skipped; an import never overwrites those paths.
Imported items receive new IDs and server revisions. Each item, local history
and pending change commits in one SQLite transaction. Repeating an interrupted
import preserves committed items, skips those paths, and drains pending changes.
Successful completion means the destination has no remaining pending changes.
