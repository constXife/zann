# ADR 0009: Cryptographic format lifecycle — Pre-GA single-v1 vs post-v0.Y append-only

- **Status:** Accepted
- **Date:** 2026-11-13
- **Scope:** `crates/zann-crypto`, `crates/zann-keystore`, `crates/zann-db`,
  `crates/zann-client`, `crates/zann-client-sqlite`, `crates/zann-server`, and
  `tests/fixtures/crypto/`
- **Related:** [ADR 0001](0001-shared-client-core.md),
  [ADR 0002](0002-client-strategy.md),
  [`docs/audit-surface.md`](../audit-surface.md)

## Implementation status

Accepted policy does not mean every hardening item below is implemented.
As of 2026-11-13, `zann-crypto` has a single `BLOB_VERSION = 1` envelope and
`tests/fixtures/crypto/v1_local_vault.json` is exercised by
`crates/zann-crypto/tests/compatibility.rs`. `LocalVault::open` still invokes
`migrate_local` without an automatic pre-migration snapshot. NFC normalization,
forward-safe payload handling, broader fixtures, systematic
`Decrypt-Before-Commit`, pre-migration snapshots and complete canonical/server
plain import/export remain required implementation work.

An intentional format cutover must wait for the lossless export/import path
and its round-trip tests; this documentation change does not authorize a
cutover or change any persisted bytes.

The #244 implementation candidate adds paged shared-server export and symmetric
atomic import, with a PostgreSQL round-trip of 132 current typed items under a
new SMK and destination UUID. Its exact preservation scope and excluded server
state are documented in [Shared server vault backups](../Server-Backups.md).
This realizes the server item-data prerequisite in section 3; it does not
implement NFC or authorize deploying the separate #245 candidate before this
recovery path has landed and the operator has exported with the old derivation.

## Context

In a password and secret manager, an accidental change to key derivation, AEAD
associated data (AAD), binary envelope framing, or encrypted JSON payload
decoding is catastrophic: valid ciphertexts become permanently undecryptable
even when the user holds the right password or server master key (`ZANN_SMK`).

At the same time, Zann is **Pre-GA** prior to `v0.Y`:

1. Incrementing `BLOB_VERSION` (`v2`, `v3`, …) on every pre-release refinement
   would permanently accumulate dead cipher/envelope branches inside
   `zann-crypto`, widening the security audit surface for zero external users.
2. Relying on plaintext export/import across Pre-GA changes works **only when a
   format change is intentional** (so the operator exports plaintext on the old
   binary *before* upgrading). An unintentional change introduced during a
   refactor or LLM-assisted edit would break existing vaults without warning.
3. Even without changing `XChaCha20-Poly1305` or `Argon2id`, user data can be
   lost through surrounding seams: strict `#[serde(deny_unknown_fields)]` on
   `EncryptedPayload` across mixed client versions, cross-platform UTF-8 NFC vs
   NFD password byte differences, unverified key re-wrapping, or schema
   migrations mutating `local.sqlite` before a snapshot is taken.

## Decision

### 1. Two-phase envelope lifecycle (`Pre-GA` vs `Post-v0.Y`)

- **Pre-GA (until `v0.Y`):**
  - Keep a **single clean `v1`** (`BLOB_VERSION = 1` and `EncryptedPayload.v = 1`).
    Do not introduce `v2` compatibility branches solely for pre-release churn.
  - **No silent mutations:** `tests/fixtures/crypto/` and
    `crates/zann-crypto/tests/compatibility.rs` remain mandatory CI **tripwires**
    against accidental byte, endianness, KDF, or AAD drift.
  - **Intentional Pre-GA breaking changes** to `v1` must:
    1. carry `!` / `BREAKING CHANGE:` in the commit/PR;
    2. follow an explicit operator migration path (`plaintext export` on the
       previous binary → wipe/recreate storage → `plaintext import` on the new
       binary);
    3. regenerate the golden fixtures in the same change.

- **Post-`v0.Y` (stability policy active):**
  - **`v1` becomes strictly Append-Only and frozen.** `parse_v1_envelope`,
    `decrypt_v1_envelope`, `v1_payload_aad`, `vault_key_aad` (`zann:vault_key:v1`),
    `payload_aad` (`zann:payload:v1`), `rotation_candidate_aad`
    (`zann:rotation_candidate:v1`), DWK wrap AAD (`zann:dwk:wrap:v1`), and
    `Argon2id V0x13` semantics are never modified in-place.
  - Any future algorithm, KDF, or envelope change is introduced as a new
    explicit version (`BLOB_VERSION = 2`, etc.) while keeping `v1` decryption
    and golden tests indefinitely.

### 2. Mandatory pre-`v0.Y` hardening inside `v1`

Before `v0.Y` freezes `v1`, the following sharp edges are resolved in-place so
`v1` ships clean:

1. **UTF-8 NFC password canonicalization:** Normalize password inputs to UTF-8
   NFC before `Argon2id` derivation so identical characters typed on macOS/iOS
   (NFD) and Linux/Windows (NFC) derive identical keys.
2. **Version-gated, forward-safe `EncryptedPayload`:** Check `payload.v` before
   field deserialization. An older client encountering an item with a newer
   schema version surfaces a typed `UnsupportedPayloadVersion(v)` and refuses to
   overwrite that item, rather than treating it as corrupt or silently dropping
   unknown fields during edits.
3. **Complete golden fixture corpus:** Extend `tests/fixtures/crypto/` beyond
   `v1_local_vault.json` to lock down:
   - `zann-keystore` DWK wrapping (`zann:dwk:wrap:v1`) and FIDO2 `hmac-secret`
     `blake3::derive_key` derivation;
   - server peppered password and service-token hashes (`hash_password`,
     `hash_service_token`);
   - `rotation_candidate_aad` ciphertexts;
   - backup format round-trips.
4. **Shell crypto consolidation (Complete, #249):** The legacy Tauri crypto
   implementation is deleted and MIG-004 is retired. Keep `zann-crypto` as the
   sole client owner of AADs and envelopes.

### 3. Plaintext round-trip completeness as a Pre-GA precondition

Because Pre-GA `v1` cutovers rely on plaintext export/import rather than
multi-version envelope branches, the export/import lifecycle must be lossless
across active vaults:

- Canonical `LocalVault` (`zann-client` / `zann-client-sqlite`) must support
  importing plain backups into server-backed storages (preserving item metadata
  including `tags` and `favorite`), retiring the Tauri-only `plain_import_remote`
  path.
- `zann-server` must pair `zann-server export` with a streaming export path (not
  capped at 120 items) and a symmetric `zann-server import` for shared vaults.

### 4. Runtime safety invariants (all stages)

1. **Decrypt-Before-Commit on key re-wrapping and rotation:** Any operation that
   re-wraps a `vault_key`, changes a master password, or rotates `ZANN_SMK`
   must trial-decrypt the newly produced ciphertext in memory with the target
   key and verify byte-for-byte equality against the source key/plaintext
   *before* committing the database transaction.
2. **Automatic pre-migration SQLite snapshot:** When opening an existing local
   vault database that has pending SQLite schema migrations, take a consistent
   snapshot (`.sqlite` + `.identity.json`, exempt from immediate retention
   pruning) *before* running `migrate_local`.

## Alignment and verification

The engineering invariants in `AGENTS.md` and the capability map remain the
review criteria; this ADR adds no second crypto or persistence owner.

- **Envelope lifecycle and golden fixtures:** reuse `zann-crypto` and its
  compatibility suite. The security cost of a single mutable Pre-GA `v1` is an
  explicit export/import cutover; no change may rely on that path until the
  completeness requirements in section 3 are tested.
- **NFC and payload version handling:** implement them in the existing KDF and
  payload owners. Unicode-equivalence and unknown-version refusal tests must
  prove the behavior. NFC changes existing password derivation semantics and
  therefore uses the same intentional-cutover gate, not a shell-specific fix.
- **Decrypt-Before-Commit:** reuse the existing encrypt/decrypt primitives in
  the owning mutation. Add one in-memory verification per new ciphertext and
  prove that failed verification leaves persisted state unchanged.
- **Migration snapshots:** reuse the SQLite maintenance snapshot and identity
  sidecar mechanisms. A pending upgrade adds a database-sized disk copy; take
  it once before mutation and fail the upgrade if it cannot be secured. Prove
  that a failed migration leaves a restorable snapshot.
- **Lossless import/export:** extend the canonical backup ports and server CLI
  owners with bounded streaming and metadata-preserving round-trip tests.
  Canonical server-backed backup import is implemented (#243); the retired
  Tauri import/crypto copies and their allowlists are deleted (#249).

These checks belong to the corresponding implementation changes. No new
runtime dependency, global coordination service or release approval step is
introduced by publishing this policy.

## Consequences

**Good.**
- Zero legacy envelope bloat (`v1`..`vN`) prior to `v0.Y`.
- Accidental crypto/serialization regressions still fail `cargo test`
  immediately via golden tripwires.
- Post-`v0.Y` upgrades gain structural protection against both compile-time
  drift (append-only envelopes + frozen corpus) and runtime bugs
  (`Decrypt-Before-Commit` + pre-migration snapshots).

**Bad.**
- Any intentional Pre-GA change to `v1` requires explicit plaintext
  export/import of developer/dogfood vaults rather than transparent lazy
  re-encryption.
