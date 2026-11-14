# ADR 0010: One device unlock password and independent account keys

- **Status:** Accepted
- **Date:** 2026-11-14
- **Scope:** `zann-client::app`, `zann-client-sqlite`, `zann-db`, native shells
- **Related:** [ADR 0002](0002-client-strategy.md), [ADR 0008](0008-device-unlock.md)
  (proposed unlock lifetime/UV policy), [ADR 0009](0009-crypto-format-lifecycle.md)

## Context

Measured in the preceding implementation: `LocalVault::unlock` derived one key
from the global Config v2 account identity. Items, server sync, remembered unlock
and backup used that same key. Authentication rejected a second KDF identity.
Changing that password therefore could not be a local operation without also
changing account encryption or losing access to existing replicas.

The requested product contract is one Zann unlock screen, independent account
keys, and an offline password-change action in Settings. Server authentication
and personal-vault E2EE remain separate trust boundaries. The server must never
receive the device root, personal keys, or personal plaintext.

## Decision

1. Generate a stable random device root. A password-derived KEK seals it using
   the existing verified `zann-crypto` v1 envelope. The device password has its
   own random salt and bounded Argon2id parameters, independent of all accounts.
   New passwords require eight NFC characters and no leading/trailing Unicode
   whitespace. Internal spaces remain significant; unlock never trims input.
2. Keep each account's existing E2EE key and remote personal-vault envelopes.
   Derive that key from its account encryption password and authenticated KDF
   identity, supplied once when adding the account on a device. Never silently
   reuse the server login password or Zann device password. New devices still
   need the account encryption password; device transfer/recovery is separate.
3. Store authenticated KDF identities in Config v2 per connection/profile.
   A keyring account envelope binds device, storage UUID, server ID and canonical
   account subject. Sync checks that exact binding before using the key.
   Item access, shared-cache encryption, import/export and verification resolve
   the selected storage's account key. A missing key is an explicit error.
4. Persist the encrypted keyring in the existing SQLite `metadata` row
   `device_keyring`, owned by `zann-db::local::MetadataRepo`. No new table,
   migration, file writer or credential backend is introduced. Bound reads
   precede allocation; the canonical decoder validates candidates before an
   exact-source SQLite compare-and-swap. Publish in-memory keys only after CAS.
5. Before enrollment, reuse sync's canonical prove/publish/bind capability.
   The loser of first-personal-key publication stores no keyring entry.
   Existing account fingerprints, including shared-only caches, must match.
   Hold the authorized Config generation lease through keyring CAS so profile,
   trust, identity or storage changes cannot race enrollment.
6. Password change requires an unlocked session and the current device password.
   Generate a fresh salt, verified-wrap the same device root, trial-open the
   complete candidate, then CAS it into SQLite. Do not modify account envelopes,
   cached payloads, account fingerprints, remote passwords, or server data.
7. Remembered unlock wraps the device root, so Touch ID/FIDO enrollment survives
   a normal password change. Lock clears all account keys and cancels reads and
   enrollment/sync work. Root verification rejects a stale remembered key.
8. SQLite snapshots contain their keyring in the same consistent read as the
   cache. Restore validates the embedded keyring before replacing the database,
   stays locked, and disarms remembered unlock. No external identity sidecar or
   cross-file config commit remains. Historical snapshots retain their historical
   unlock password; changing today's password is not erasure of old copies.

The crypto algorithms and existing account/vault v1 formats do not change. The
new local key hierarchy and Config v2 shape are an intentional Pre-GA cutover;
see [export/import instructions](../migrations/device-unlock-keyring.md).

## Consequences and verification

One device password opens all enrolled accounts offline. An account can later
get a separate unlock policy without re-encrypting its data. Password changes
are one bounded local CAS, with no partial multi-server rotation to recover.

Costs: first-device setup distinguishes device unlock from account encryption;
adding another device needs the account encryption secret. There is no new
password-reset, recovery, key transfer, or account-key rotation protocol here.
The server-oriented CLI remains independent of the device keyring.

Required evidence includes independent two-account reads/export after restart
and password change; wrong-password/stale-CAS rejection; enrollment publication
races; account/subject isolation; remembered-root continuity; consistent snapshot
restore; Rust/Swift/native build checks; architecture and audit gates.

## Values interrogation

This repository has no separate values manifest or ADR template. The governing
tests are the invariants in `AGENTS.md`, Architecture and the capability map.
Each lever is evaluated independently:

| Lever | Trust separation and custody | SSoT and consolidation | Crash safety and bounded work | Cost / extensibility |
|---|---|---|---|---|
| Random device root and password wrapper | Only local ciphertext; no server-held unlock material | Existing crypto API; one app owner | Verified candidate and one CAS | One extra wrapping layer permits future unlock policies |
| Per-account identity and key slots | Server/account/storage AAD prevents substitution | Replaces global account identity; no shell KDFs | Bounded map and strict decode | One-time enrollment secret is explicit |
| Canonical key proof and Config lease | Proves first personal key and existing shared-cache binding | Reuses sync publication and generation gate | Publication loser keeps no bag; writers excluded through CAS | No parallel enrollment protocol |
| SQLite metadata custody | No plaintext key persistence | Reuses existing repository and table | Exact-source CAS; no schema migration | Adds two general bounded/CAS metadata operations |
| Stable remembered root | OS/hardware protections stay local | Existing keystore/authenticator ports | Root check rejects stale state | Password change needs no second OS write |
| Embedded snapshot keyring | Encrypted recovery material travels with its data | Deletes identity sidecars and config restore writes | One SQLite snapshot/restore boundary | Old snapshots use their original password |
| Password validation and Settings form | Current password required; no silent trimming | NFC stays in crypto, policy in shared app, form confirms only | Invalid input writes nothing | Eight-character policy and Unicode edge-space rule are explicit |
