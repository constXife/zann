# Pre-GA cutover: device unlock keyring

This change replaces the global Config v2 `identity` with authenticated
`account_identities` per connection/profile. The encrypted device keyring lives
inside the SQLite database. Existing personal/server ciphertext formats and
server passwords do not change.

A previous Config v2 file containing a global identity is refused with an
explicit export/import message. It is never overwritten or converted in place.
There is no automatic password inference, compatibility reader or dual write.

Before using this build with existing data:

1. Use the preceding build to sync and export current items from every account.
   Keep its encrypted database, config and unlock state together as a private
   recovery copy. Do not delete or move the only copy of unsynced data.
2. Use a fresh client root for this build. Sign in to the server, create one
   Zann unlock password, then enter the account's existing encryption password.
   Adding subsequent accounts keeps the same Zann unlock password.
3. Let server sync restore the catalog and confirmed items. Import a plaintext
   export into its intended account only when needed for local unsynced items.
   Verify names, fields, tags, favorites and item counts before retiring the old
   client copy. Reconnecting to a server does not rotate its account keys.
4. Keep plaintext exports owner-only and remove them when no longer needed.

The JSON item export preserves current typed item values and metadata within
its documented scope; it does not export full item history, attachments, ACLs,
or account sessions. Keep the old encrypted client copy for that historical
material. Never describe an item export as a complete server/database backup.

In the new build, an encrypted SQLite snapshot is self-contained: it includes
its keyring. Restoring it restores the Zann unlock password saved in it and
requires unlocking again. Password changes affect this device only; existing
snapshots and other devices keep their respective passwords. Account encryption
passwords remain necessary when enrolling the account on another device.
