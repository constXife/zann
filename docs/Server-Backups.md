---
title: Shared server vault backups
description: Streaming plaintext export and atomic recovery under a new server master key.
---

`zann-server export` and `zann-server import` use the same shared plaintext
JSON format (`version: 1`, `scope: "shared"`, `plaintext: true`). These are
privileged local maintenance commands using the configured database and
`ZANN_SMK`; they are not HTTP endpoints. Personal client-encrypted vaults are
excluded and explicit personal-vault selections are refused.

## Export on the old installation

Stop writers for the recovery procedure and retain a database backup, the old
binary, identity key and old SMK separately. Use a private directory that
already exists:

```sh
zann-server export --all-shared --include-deleted \
  --out /secure/backups/shared.json --i-understand-plaintext
```

Use repeated `--vault <slug-or-UUID>` instead of `--all-shared` to select
vaults. Without `--include-deleted`, only active items are exported. Without
`--out`, the completed export streams to stdout; secure its destination.

Vault selection, counts and 32-row cursor pages share one
`REPEATABLE READ, READ ONLY` snapshot. A scalar size preflight bounds each page
before ciphertext is loaded. Payloads are decrypted one at a time. The old
120-item / 32-MiB aggregate limits are removed; the format's explicit admission
bounds are 4,096 vaults, 1,000,000 items and 2 MiB per JSON record. The canonical
256-KiB typed-payload and item-metadata bounds still apply. Exceeding a bound
fails the export; no rows are silently omitted.

Output is staged in a private `0600` file, flushed and synced before atomic
replacement of `--out`. Export failure before publication leaves an existing
backup intact and removes the partial staging file. The parent directory must
already exist. Plaintext is never written to a permissively created temp file.

## Import on the destination

Migrate the destination database, configure its new SMK, and create the active
account that will administer recreated vaults before importing. Keep writers
stopped. Input must be an owner-only regular file; symlinks, hard-link aliases
and files granting group/other access are refused.

```sh
zann-server import --input /secure/backups/shared.json \
  --owner-email owner@example.com --i-understand-plaintext
```

The complete source is streamed through schema, version, bounds, timestamp,
count and duplicate-key/identity/path validation before any database write.
Validated records go to a private anonymous staging file, pinning the actual
admitted content. Only bounded vault headers and duplicate-detection keys stay
in memory. JSON diagnostics retain their original error internally while
rendering only safe location information; secret values never appear in errors.

Destinations match by exact vault slug. A matching target must be an undeleted,
empty shared server-encrypted vault, including no tombstones. Its UUID, name,
key, policy and membership remain in place. Missing vaults are recreated using
the backup UUID/slug/name, a fresh vault key, full-cache policy, empty vault tags
and the explicitly supplied account as admin. Imported item UUIDs are retained;
an existing global UUID or path collision fails the transaction rather than
overwriting a record. Repeated import into an occupied destination is refused.

Import is one transaction. Maintenance table locks serialize it with vault/item
writers. New keys and payload ciphertexts are trial-decrypted under their target
key and UUID-bound AAD and compared before persistence. Checksums are recomputed.
Devices, membership, vaults, items and the sync change generations commit
together; any failure rolls all of them back. No export-supplied key or old SMK
is installed on the destination.

## Preservation scope

The round-trip preserves every exported current typed item's UUID, path, name,
type ID, tags, favorite, payload fields/metadata/extra, version, deletion time
and update time, including more than 120 records. Deleted records require the
explicit export flag. New ciphertext and ciphertext checksums differ by design.

This v1 format does not contain item history, attachments, vault tags/cache
policy/creation time, users/password hashes, sessions/tokens, ACLs or server
identity. Those require retention of the old database, keys and binary; this
file is not a whole-server backup. Personal data uses the canonical client
backup path separately. For a password-KDF cutover, recreate authentication
credentials through the new installation's normal account flow.

After import, verify item counts and metadata, unlock/authentication, secret and
item reads, and client sync before retiring the old installation. Keep secured
backups until verification completes and remove plaintext exports according to
the operator's secret-data handling policy. See [ADR 0009](adr/0009-crypto-format-lifecycle.md).
