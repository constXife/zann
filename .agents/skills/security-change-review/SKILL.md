---
name: security-change-review
description: Review T2 changes touching Zann's security audit surface, cryptography, keystore, auth/sync protocols, trust boundaries, or FFI exports. Verify personal vs shared vault isolation, secret redaction, TOFU pinning, and crash-safe state transitions.
---

# Security & Trust-Boundary Review (Zann)

Use this read-only procedure on **T2** changes (any diff touching paths in
[`docs/audit-surface.md`](../../../docs/audit-surface.md), `zann-crypto`,
`zann-keystore`, `zann-client` auth/sync/config/delivery, `zann-client-sqlite`,
`zann-server` auth/access-control/audit, `zann-ffi`, or architecture boundary
rules) or when explicitly requested.

Normative references:
- [`crates/zann-server/SECURITY.md`](../../../crates/zann-server/SECURITY.md)
- [`docs/audit-surface.md`](../../../docs/audit-surface.md)
- [`docs/architecture/capabilities.md`](../../../docs/architecture/capabilities.md)
- [`docs/adr/0002-client-strategy.md`](../../../docs/adr/0002-client-strategy.md)
- [`docs/adr/0009-crypto-format-lifecycle.md`](../../../docs/adr/0009-crypto-format-lifecycle.md)

## Checklist of Zann Security Invariants

### 1. Personal (`Client`) vs Shared (`Server`) Vault Boundary
- **Personal vaults (`VaultEncryptionType::Client`)** are end-to-end encrypted
  on the client. Verify that personal master keys, vault keys, and decrypted
  payloads never cross into server-readable endpoints, web-console surfaces, or
  service-account paths.
- **Shared vaults (`VaultEncryptionType::Server`)** are decrypted by the server
  via `ZANN_SMK` and re-encrypted locally before SQLite persistence in
  `zann-client-sqlite`. Verify that prefix/scope access control and
  service-account restrictions cannot be bypassed.

### 2. Secret Custody & Redaction
- Plaintext passwords, master keys (`SecretKey`), device wrapping keys, KDF
  salts/outputs, OIDC codes, and access/refresh/service tokens must **never**
  appear in:
  - `Debug` implementations (check custom `fmt::Debug` on UI messages such as
    `apps/cosmic/src/screens/editor.rs` and request structs);
  - tracing/log fields, panic messages, or user-visible error strings;
  - CLI command-line arguments (`argv`) or world-readable files.
- Files holding configs, credentials, snapshots, or plain exports must enforce
  owner-only modes (`0600` for files, `0700` for directories on Unix) and reject
  symlinks/hard-links where required by `zann-client` and `zann-client-sqlite`.
- UI clipboard operations must honour generation-checked auto-clear timers and
  clear-on-lock policies; temporary reveal (`Shift` / `Option`) must reset on
  key release and window focus loss.

### 3. Cryptography & KDF Integrity (`zann-crypto`)
- All KDF, AEAD (`ChaCha20-Poly1305`), and payload checksum operations must
  route through `zann-crypto` (no ad-hoc wrappers in shells or `zann-ffi`).
- Verify that AAD bindings (vault ID, item ID, key fingerprints) and resource
  bounds on persisted KDF parameters are validated before execution.
- Enforce [ADR 0009](../../../docs/adr/0009-crypto-format-lifecycle.md) format
  safety:
  - No silent changes to `EncryptedBlob`, KDF, AAD, or `EncryptedPayload`
    encoding: Pre-GA intentional `v1` updates require `!` / `BREAKING CHANGE:`,
    lossless plaintext export/import instructions, and updated golden fixtures
    in `tests/fixtures/crypto/`; post-`v0.Y` changes must add a new
    `BLOB_VERSION` without altering `v1` decryption.
  - Key re-wrapping and rotation paths (master password, `vault_key`,
    `ZANN_SMK`) must trial-decrypt the new ciphertext in memory and verify
    equality before committing (`Decrypt-Before-Commit`).
  - Schema/storage migrations on existing vaults must not overwrite user data
    without a pre-migration snapshot or fail-closed export gate.
- Ensure `scripts/check-audit-surface-deps.sh` passes without widening
  `zann-crypto`'s dependency closure unnecessarily.

### 4. Authentication, TOFU & Crash-Safe State (`zann-client`)
- Verify lock nesting order (`auth_lock -> credential_lock -> config_lock`):
  code holding the config lock must never perform network or OS-keystore I/O.
- Check that `client-auth.intent.json` and `client-config.credential-intent.json`
  preserve fail-closed crash recovery (no automatic blind retry of ambiguous
  in-flight token refresh or password login).
- Ensure server fingerprint changes require an explicit TOFU compare-and-replace
  trust decision (`ConnectionTrustChallenge`) before credentials are sent.

### 5. Local SQLite & Sync Integrity (`zann-client::sync` & `zann-client-sqlite`)
- Pull and push pages must validate wire payloads and account/capability
  bindings (`personal_vaults_enabled`, canonical `/me.user_id` + `AuthMethod`)
  before local SQLite mutation.
- Cursor, `last_seq`, vault key fingerprint CAS, and Config v2 generation proof
  must advance atomically inside the same `BEGIN IMMEDIATE` transaction.
- Detached commit tasks must survive caller future drop and surface ambiguous
  failures as `CommitOutcomeUnknown` rather than silently retrying.

## Report Format

```markdown
### Security Review: <scope>
**Verdict:** PASS | FINDINGS | NEEDS EVIDENCE
**Inspected:** <files / commits>

1. **Trust & Data Flow Trace:**
   - <entry point -> boundary -> storage/network hop>
2. **Findings:**
   - [HIGH|MED|LOW, introduced|preexisting] `<path>:<line>` — <violated invariant, exploit scenario, and minimal fix>
3. **Verification:**
   - <exact commands run or required regression test>
```
