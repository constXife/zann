# ADR 0015: Explicit account scope for plaintext export

- **Status:** Proposed
- **Proposed:** 2026-11-15
- **Scope:** `zann-client::app::local`, `zann-client-sqlite::maintenance`, native export and FFI
- **Related:** [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0011](0011-account-scoped-replica-bindings.md) (Proposed)

This proposes an export-scope change. Existing multi-account export is intentional
behavior, not evidence that account keys are still global.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [backup_export_file](../../crates/zann-client-sqlite/src/local_vault/maintenance.rs)
  takes a path but no storage scope.
- [plain_export](../../crates/zann-client-sqlite/src/maintenance/backup/export.rs)
  enumerates all storages/vaults and resolves their respective account keys.
- The [restart/password-change regression](../../crates/zann-client-sqlite/src/local_vault/context_tests.rs)
  intentionally exports both accounts. Import already requires an explicit target storage.
- The existing [migration guide](../migrations/device-unlock-keyring.md) distinguishes
  current-item JSON export from a complete backup; full history, attachments, ACLs
  and sessions are not included.

A user exporting one account should not unintentionally disclose another account's
items or identifying metadata in the same plaintext file.

## Proposed decision

1. Require an explicit account/storage argument for the standard native plaintext
   Export action, carried through the existing local port and FFI. Show that scope
   before writing. The serializer must include only that storage's metadata, vaults
   and items, using its bound account key. A missing/changed target is an error,
   never a request for all accounts or the currently selected account.
2. Reuse the canonical paged exporter, typed backup format and private-file writer.
   Pin/capture the account source and reject cancellation or a superseded binding;
   a failed export must not be presented as a completed file. No parallel export
   implementation or automatic scope fallback is added.
3. Keep SQLite snapshots device-wide and self-contained under ADR 0010. Preserve
   the documented JSON preservation/exclusion scope and matching import path.
   If an explicit all-account export is retained as a product action, it must use
   the same exporter with visibly explicit scope; it cannot remain an implicit default.

## Acceptance questions and evidence

- Decide whether to retain an explicit all-account action, and define the single
  scope contract/API cutover for every consumer. Update the existing multi-account
  test deliberately; do not hide the behavior change behind a default argument.
- Test two populated storages and prove the selected export contains no other
  account's metadata, vault names or items. An unrelated missing key must not block it.
- Test stale target, lock/removal, paging, private permissions, cancellation and
  incomplete-output cleanup. Round-trip current typed values, tags, favorites and
  versions through canonical import to the explicitly chosen target.
- Document actual export limits and exclusions; do not advertise this as complete
  database/server recovery or a change to encrypted snapshot behavior.

## System alignment review

- **Reuse:** `LocalVaultService`, maintenance exporter/streamer, secure file writer,
  current backup schema and explicit-target importer.
- **Justified divergence:** output scope is a disclosure decision separate from
  the storage-specific key resolution already implemented by ADR 0010.
- **Realign on implementation:** native/FFI signatures, export UI and existing
  all-account tests move together. No new backup format is justified by scoping alone.
- **Aligned as-is:** embedded snapshot keyring, per-account verification and the
  existing documented limits of plaintext item export.

## Values interrogation

Apply the custody, SSoT, bounded-work and lossless-cutover tests in
[AGENTS.md](../../AGENTS.md) and ADR 0009.

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Explicit account scope | Prevents cross-account plaintext/metadata disclosure | One required scope on the canonical port | Captured binding cannot follow a UI switch | API cutover required; assert absence of a second account's data |
| Shared paged/private writer | Plaintext remains owner-only; no secret logging | Reuse serializer/import contract rather than a new exporter | Bounded pages and incomplete-file cleanup are required | No extra full-data pass; test cancel/failure and round-trip |
| Distinct snapshot and export actions | No claim that item JSON replaces encrypted recovery material | Keep existing snapshot owner and backup format | Snapshot still captures its keyring consistently | Explicit all-account UX remains an acceptance decision below |

## Consequences, debt and alternatives

Ordinary export becomes narrower and auditable. Exporting several accounts may
require an explicit batch choice or separate files; it must not require unrelated
keys or scan unrelated payloads for a single-account request. Streaming and the
current serializer keep memory/cost tied to the requested data.

**Deferred until acceptance:** whether an explicit batch action remains, its
consumer contract and incomplete-output publication rules. These decisions belong
here before implementation; this documentation changes neither API nor file bytes.

Rejected: silently exporting all unlocked accounts, filtering plaintext after a
full-device export, or introducing another serializer/format for the same items.
