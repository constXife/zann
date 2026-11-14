# Pre-GA v1 password NFC cutover (#245)

**BREAKING CHANGE:** `zann-crypto::derive_auth_hash` normalizes passwords to
Unicode NFC before Argon2id. Canonically equivalent NFC/NFD input now derives
the same key. Spaces, case and compatibility characters remain significant;
opaque service tokens and peppers are not normalized.

Passwords previously stored in a non-NFC form can derive a different master
key or authentication hash after this change. Existing ciphertext does not
become decryptable merely by retyping that password. The binary envelope and
AAD remain `v1`; there is no legacy derivation fallback or automatic rewrite.
The original ASCII `v1_local_vault.json` remains unchanged.

## Release prerequisite

The recovery prerequisite [#264](https://github.com/constXife/zann/pull/264) is
merged as `11d4f447`. It implements #244 and verifies the shared-server recovery
path with a 132-item PostgreSQL round-trip. Build that pre-NFC revision and export
**before upgrading** to the NFC change, as required by
[ADR 0009](../adr/0009-crypto-format-lifecycle.md).
The export binary must contain #244 while retaining the old, raw UTF-8 password
derivation. Canonical client backup import (#243) supplies the personal-data
path. Exact shared-backup commands and preservation scope are documented in
[Shared server vault backups](../Server-Backups.md).

## Operator sequence after that prerequisite is satisfied

1. Keep the old binaries, configuration, encrypted backups and keys available.
   Stop writers and use the **old** binaries to export every personal and shared
   vault to plaintext through the tested, complete export path. Store exports
   with owner-only access (`0600` files, `0700` directory).
2. Verify completeness and the tested round-trip contract before replacing any
   storage. Include item metadata and confirm which history or administrative
   state requires retention in the old encrypted backup. Never erase the only
   readable copy.
3. Recreate storage and credentials with matching new client/server binaries,
   then import through the completed canonical paths. This also recreates
   server password hashes under NFC semantics. Do not mix old and new password
   derivation across a deployed client/server pair.
4. Verify unlock, authentication, restored item counts, metadata and sync before
   retiring the old installation. Retain secured backups until verification is
   complete; remove plaintext exports according to the operator's secret-data
   handling policy.

The shared v1 file preserves current typed items and metadata; retain the old
encrypted database and keys for history, attachments and administrative state
outside that format. This migration contract does not instruct an operator to
erase an existing installation before the recovery prerequisite has landed.

## Independent safety changes

Payload decoding checks `v` before decoding the current field schema and
returns `UnsupportedPayloadVersion(v)`. Local edits compare the exact admitted
source row inside the transaction that writes the item, history and pending
intent. Server shared-item mutations admit the locked source payload; personal
ciphertext stays opaque to the server. Unsupported items are refused rather
than rewritten through an older schema.

Key wrapping and rotation writers trial-decrypt each candidate under its
target key and AAD, then compare plaintext before publishing it. Remembered
unlock proves the wrapped master key before replacing the device wrapping key.
