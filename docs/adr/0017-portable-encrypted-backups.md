# ADR 0017: Local export authorization and portable encrypted backups

- **Status:** Accepted
- **Date:** 2026-11-15
- **Scope:** `zann-crypto`, `zann-keystore`, `zann-client::app::local`, `zann-client-sqlite`, native shells and FFI
- **Related:** [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted), [ADR 0010](0010-device-unlock-account-keys.md) (Accepted), [ADR 0015](0015-account-scoped-plaintext-export.md) (Proposed; export scope remains unchanged), #297, #298, #292

## Context

Measured: the canonical native serializer pages items and writes JSON to `Write`;
canonical restore validates then streams items into the existing server-backed
import session. SQLite snapshots preserve the local replica and encrypted
keyring; they are not portable encrypted archives. The OS remembered-unlock key
has a different lifetime and purpose from a portable backup recipient.

Measured: #297 replaces path-only plaintext export with fresh local factors and
one-use 120-second permits bound to session generation, keyring, policy and
cancellation. Both native shells present warning and confirmation before file
creation. The service owns persisted strict policy and last-factor protection.

The repository has no separate values manifest. The decision follows AGENTS.md,
the capability map and the architecture's security, custody, ownership,
crash-safety and bounded-resource invariants.

## Decision

1. **A separate archive v1, owned by `zann-crypto`.** This does not change Item
   envelopes, KDF identities or the golden fixtures of ADR 0009. A fresh random
   32-byte DEK encrypts a canonical backup JSON stream. The binary prefix identifies
   archive v1; a bounded JSON header describes at most 16 recipients. Unknown
   versions, algorithms, fields and malformed descriptors fail closed.
2. **Authenticated header and independently wrapped slots.** Each slot uses
   ChaCha20-Poly1305 with a random nonce; its AAD includes archive identity and
   the complete ordered descriptor context. Every new wrap is trial-unwrapped
   and compared before output. A DEK-derived header key authenticates the complete
   serialized header, including every wrapped slot. Recipient removal/substitution
   cannot silently change the accepted archive policy.
3. **Bounded authenticated frames.** DEK-derived payload key and monotonic frame
   index nonces; AAD binds the authenticated header, frame index, length and final
   marker. Payload frames contain at most 64 KiB. An authenticated empty final
   frame is mandatory, followed by EOF. Truncation, reordering, append and bit
   changes fail. Plaintext frame buffers are erased on drop.
4. **Recipient custody and anti-lockout.** Passphrases use the existing NFC
   Argon2id owner, independent random salts and validated bounded parameters.
   Hardware descriptors use fresh hmac-secret credentials/salts and a backup-
   specific derived-key context; PIN/UV is explicit per operation. Biometric
   recipients use a dedicated platform key namespace guarded by current biometric
   enrollment, never the remembered-unlock DWK. The core refuses biometric-only
   archives before touching output. Each archive requires a passphrase or hardware
   recipient; native UI encourages a passphrase or second key for recovery.
5. **One serializer and importer.** Export encrypts directly into the private
   atomic output writer. Restore and dry-run reopen authenticated readers over
   the encrypted source; no plaintext temporary file or whole-vault RAM buffer.
   Recipient confirmation unlocks a bounded archive handle; subsequent parser
   passes reuse that handle without repeated native prompts. Complete validation
   finishes before any import mutation. All key-bearing operations carry session
   generation and cancellable operation admission.

## Per-mechanism invariant interrogation

- **Permits:** security gains fresh factor proof at the owning service; custody
  keeps secrets local; ownership removes path-only bypasses; crash safety burns
  permits on failure; bounds are one pending permit and 120 seconds. Replay,
  cancellation and lock tests discriminate the mechanism.
- **Slots/header:** security binds every recipient and its context; custody keeps
  only wrapped DEK on disk; one crypto owner serves all clients; trial unwrap
  precedes publication; 16 slots and 64 KiB header cap resource use. Slot/header
  mutation and multi-recipient tests distinguish authenticated policy from labels.
- **Frames:** AEAD plus final frame proves complete ordered plaintext; buffers
  erase on drop; one `Read`/`Write` codec replaces shell encryption; atomic private
  publication preserves the previous destination on failure; 64 KiB bounds RAM.
  Boundary-size, reorder, truncation and trailing-data tests distinguish success.
- **Recipient adapters:** portable recipients guarantee recovery independent of
  the originating biometric device; dedicated keys separate purposes; canonical
  KDF and authenticator ports avoid shell cryptography; failed enrollment changes
  no archive; bounded parameters and explicit prompts constrain work. Biometric-
  only refusal, fresh biometric cancellation and multiple hardware tests verify it.
- **Reopenable input:** complete authentication/validation precedes mutation;
  plaintext stays in bounded buffers; one importer remains the owner; failed reads
  create no restore records; each pass is bounded and cancellable. Tampered
  archive dry-run/import tests distinguish a safe failure from partial restore.

## Alignment and consequences

Reuse the existing serializer, canonical restore session, crypto/KDF owner,
platform ports, operation cancellation and private output publisher. Delete
path-specific parsing assumptions when introducing reopenable input. Shells own
factor input, native prompts, warnings and file selection only.

The cost is several sequential authenticated parsing passes during restore;
this preserves bounded memory and full preflight. There is no plaintext cache,
compatibility reader, automatic recovery factor or silent policy downgrade.
Biometric access is local convenience and can be invalidated by enrollment
changes; portable slots are mandatory. Hardware-device and Apple biometric
qualification require physical devices; deterministic fake-port tests cannot
claim those results.

A biometric metadata CAS is awaited outside the session gate. If its commit is
ambiguous or another enrollment wins, retain the newly created private OS entry:
blind cleanup could delete the key referenced by a durable row. Failed read-back
verification before CAS removes its uncommitted key. An abandoned key entry is
preferable to a dangling reference; there is no automatic key replacement.
The native port projection was extracted into `local_vault::service`; its one
existing `AppClient` return type moves with the projection, while the architecture
guard retains the same maximum match count and construction owner.
