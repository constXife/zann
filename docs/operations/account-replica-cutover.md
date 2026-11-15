# Account-scoped replica cutover (Pre-GA)

[ADR 0011](../adr/0011-account-scoped-replica-bindings.md) moves native replica
ownership from a connection to its authenticated account profile. This is a
breaking client Config change. The server account and encryption format stay
unchanged. The new client refuses old connection-level replica fields before
opening/migrating the local database; it does not assign them to an active profile.

## Preserve and verify

1. Keep the previous working client build. With that build, unlock the old root,
   sync each account and export its plaintext JSON backup through Settings → Backups.
   Include unsent/local-only records and Trash where relevant. Export every account
   present in the old root; do not assume the selected account represents the others.
2. Keep the original root, Config backups/journals and database intact. Store copies
   and plaintext exports in owner-only directories (`0700`) and files (`0600`).
   Do not publish exports, put them in Git, or pass passwords/tokens as CLI arguments.
3. Start the new client with an explicitly selected fresh root. Connect to the
   existing server account, set the device unlock password and enroll its existing
   account encryption password. Wait for its first sync. Add another account on the
   same endpoint through Connect; use Reconnect only for an explicitly selected
   disconnected replica in a root already using the new profile format.
4. Import the old plaintext backup into the matching authenticated account/storage
   when it contains records missing from the server. Verify account, vault and item
   counts and compare exports without printing secret values. Restart and unlock
   the new client; verify offline access and another sync for every enrolled account.
5. Retain the old root/build and protected exports until verification is complete.
   Never point the previous build at the new root. This change does not delete the
   old data or choose a retention policy on the user's behalf.

If the old primary, backup or journal contains connection-level replica fields,
use the previous build to reconcile it and export. Do not hand-edit ownership,
copy an old database into the new root or remove a journal to bypass the gate.
If a remote-only Config has multiple aliases for one normalized endpoint, select
one trust owner explicitly in a fresh root rather than using aliases as accounts.
