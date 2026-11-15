# Shared-only cache key cutover (ADR 0012)

ADR 0012 changes the authenticated purpose in local account-envelope AAD. It is
an intentional Pre-GA breaking change. There is no automatic purpose inference,
legacy decoder, cache reset or in-place rekey. Server shared-vault encryption and
personal-vault crypto formats do not change.

## Before upgrading an existing client root

1. Keep the previous build (`f971881`, before ADR 0012) and its complete client
   root. Unlock it, synchronize every account when possible and export JSON from
   Settings → Backups. Export also includes current local pending items; a failed
   sync is not permission to discard them. Protect plaintext exports as secrets
   (`0600`, private parent directory); enter passwords only in the client.
2. Keep an untouched copy/snapshot of the original root and record each account's
   item counts. Export/import transfers current item data; it does not transfer
   local history, remembered-unlock enrollment or session credentials. The old root
   is the retained source for those records. Snapshots with old envelopes need
   the previous build to unlock them.
3. Start the new build with an explicitly selected fresh client root. Reconnect
   each account and choose the device-unlock password once. Shared-only accounts
   enroll random cache keys without account-password prompts. Personal-enabled
   accounts require their actual account encryption password.
4. Sync, then use JSON import with an **explicit source storage UUID from the
   backup** and the matching destination storage UUID in the new root. These UUIDs
   are different. Import only one source account into that destination, then sync
   and export again. Compare current items, fields, tags, favorites and
   counts without displaying secrets. Test lock/restart/unlock and each account.
5. Retain the old root until verification succeeds. If anything fails, stop using
   the destination and reopen the original with the previous build. Do not patch
   origin fields or fingerprints in either database/config.

An old account envelope is refused without rewriting it. An empty device
keyring has no account-envelope AAD to change. A missing/unreadable key with a
bound fingerprint is a recovery error: restore its readable root/snapshot rather
than generate a replacement key for that replica.

## When a shared-only server enables personal vaults

The current client can still unlock, read and export the existing cache offline.
Sync/import reports `account_key_enrollment_required`; it does not publish a
personal key or change the cache, fingerprint or pending changes.

Use the same retained-source/fresh-root procedure above with the **current build**.
Export the original cache before removing anything, reconnect under the enabled
policy, explicitly enroll the account's personal encryption key, sync and import.
Verify that unsent items appear in the destination export. Keep the original root
for local history and pending-state evidence. Personal enablement is never inferred
from a vault list or an account's login method.

If personal vaults are disabled after an account already enrolled a password-derived
key, keep that readable key and its purpose. No password prompt, automatic key
replacement or cache rewrite is required for that existing enrollment.

## JSON import surface

The current native Settings screens do not expose JSON import. The supported
core/FFI API is `backup_import_file(path, source_storage_id, options)`; the source
is mandatory for JSON only, while Apple CSV import keeps its existing API.
The source UUID must be chosen explicitly from the backup's `storages` metadata
using its server/account subject. Do not choose by display name or take the
first storage in a multi-account export. The destination is an authenticated
storage selected in the new root. Invalid/missing sources fail before sync or
vault preparation. Other accounts' vaults and items are excluded from the import.

For an already unlocked, connected `LocalVault`, the programmatic call is:

```rust,ignore
use zann_client::app::local::BackupImportOptions;
core.backup_import_file(
    protected_backup_path,
    source_storage_uuid_from_backup,
    BackupImportOptions { target_storage_id: Some(destination_storage_uuid) },
)?;
```

The same argument is projected by the existing FFI method. The real-server
regression in `crates/zann-integration-tests/tests/shared_cache_keys.rs` exercises
this transition including unsent data and excludes the second account. GUI JSON
import and account-scoped export are separate work; [ADR 0015](../adr/0015-account-scoped-plaintext-export.md)
remains Proposed. This guide does not assume those UI surfaces exist.
