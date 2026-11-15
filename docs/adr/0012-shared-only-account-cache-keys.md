# ADR 0012: Local cache keys for shared-only accounts

- **Status:** Accepted
- **Proposed:** 2026-11-15
- **Accepted:** 2026-11-15
- **Scope:** `zann-client::app`, `zann-client-sqlite`, native enrollment and FFI
- **Related:** [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0011](0011-account-scoped-replica-bindings.md) (Accepted)

This decision changes shared-only enrollment and account-envelope AAD in place
under ADR 0009. It adds neither another keyring nor implicit password reuse.

## Context

Measured in `main` at `f971881` on 2026-11-15:

- Native enrollment derives every account key from an account encryption password
  and authenticated KDF identity, including accounts on shared-only servers.
- OIDC and token-import session commits request account KDF material via prelogin
  unconditionally. The authenticated session already carries the pinned server's
  verified `personal_vaults_enabled` capability.
- Account envelopes bind device, storage, server and subject, but have no key-purpose
  discriminator. Sync uses the enrolled key for personal envelopes and local shared caches.
- Both native shells call `LocalVaultService::activate_connected_account` after
  device unlock and before the shared unlock flow can require an account password.
- Existing profile fingerprints and cached shared-vault envelopes must match an
  enrollment key. Replacing that key with a new random key can strand cached or pending data.

## Decision

### Authenticated policy and enrollment

`AppClient::account_key_requirement` authorizes the exact profile through the
canonical session owner. The resulting `AccountKeyOrigin` is `AccountPassword`
when the verified server capability enables personal vaults, otherwise
`LocalCacheKey`. An empty catalog, shell hint, auth method or missing KDF identity
is never evidence of shared-only policy. A failed authorization is an error.

For a fresh shared-only account, activation generates one random `SecretKey` and
uses the existing bound account envelope under the unlocked device root. The
first account still needs an explicitly chosen device-unlock password. A second
shared-only account uses that same unlocked root without any account-password
prompt or another account KDF. Activation returns the existing enrolled result;
both shells and the shared unlock routes already consume it. No extra shell
branch or FFI key-generation endpoint is needed.

OIDC and imported-session enrollment do not request prelogin KDF material when
verified policy disables personal vaults. Their authenticated subject and auth
method remain mandatory. They preserve any existing KDF identity, without
inventing one. `CredentialProfile.account_email` owns the canonical `/me` label
independently of KDF provenance, so no-KDF accounts retain distinct account labels.
Password authentication still performs its required coherent prelogin checks.

### Purpose and custody

Every account envelope requires `origin: account_password | local_cache_key`.
The origin is the fifth element of the existing unambiguous JSON tuple AAD
(device, storage, server, subject, origin). Missing or unknown origins are errors;
changing an origin without re-encryption fails authentication. Existing crypto
algorithms, `EncryptedBlob` v1 framing and remote personal-vault bytes are unchanged.
The keyring remains the bounded SQLite `metadata.device_keyring` value. Candidate
wraps are verified and the complete candidate opens before exact-source CAS.

Sync and backup-import operations carry the stored origin alongside the key.
The sync owner refuses `LocalCacheKey` when freshly authorized policy enables
personal vaults **before local target resolution, catalog reconciliation or personal
key publication**, including publication of an uninitialized personal vault.
A password-derived key already enrolled before personal vaults were disabled
remains readable and usable as its original cache key; it is never automatically
replaced or relabeled.

### Random-key publication and crashes

Enrollment captures the exact storage/server/subject and rechecks policy and
profile generation before returning a Config lease. That lease and existing
sync admission remain alive through keyring CAS. A mismatched fingerprint or an
already-bound replica without its enrolled key is refused; random enrollment
cannot take over an existing binding.

For a fresh random key, preparation verifies the shared-only catalog and resolves
the replica but **does not publish its fingerprint in Config**. Only after the
keyring CAS succeeds may normal sync bind the now-durable key. A crash or failed
CAS before publication can therefore retry with a fresh candidate; no fingerprint
points to a lost random secret. A crash after publication reopens the same key
from the keyring. There are no plaintext/pending writes in the unbound interval.
No new recovery journal, dual-write mechanism or one-shot permit is introduced.

### Existing caches and enabling personal vaults

A readable existing envelope is always reused with its original purpose. A missing
key with a bound fingerprint, wrong server/subject, unreadable cache envelope or
stale source is an error, never permission to regenerate a random key. The caller
must retain the original root/snapshot rather than reset cache or pending state.

Enabling personal vaults is **not an implicit key promotion or rotation**.
A local-cache envelope remains usable for offline reads and plaintext export, but
online sync/import returns `AccountKeyEnrollmentRequired`. The old fingerprint,
keyring, cache and pending changes stay intact. Personal-key setup is explicit in
a fresh client root: export all local items (including pending changes), sign in
under the enabled policy, supply the account encryption password, sync and import,
then compare exports before retiring the original root. JSON import requires an
explicit source storage UUID as well as the destination, so a full-device backup
cannot copy a second account into the selected account. This argument is limited
to JSON import; CSV and export scope are unchanged. Native JSON-import UI is not
implemented; the tested core/FFI operation is the present programmatic surface. See the
[cutover and policy-change procedure](../operations/shared-cache-key-cutover.md).
This deliberate refusal avoids an unbounded cache rewrite or a new cross-file
Config/SQLite key-rotation protocol. Lossless in-place rekeying is not claimed.

### Intentional Pre-GA format cutover

Old account envelopes without origin cannot be classified safely. Export with the
previous build before upgrading, then reconnect/enroll/import into a fresh client
root. The new decoder refuses the old envelope instead of guessing its purpose;
it never rewrites it. Empty keyrings contain no account AAD and retain the same
format. Snapshots with old account envelopes require the previous build for export.
The synthetic `v1_device_keyring.json` fixture intentionally changes to freeze
both origins and the new AAD; other crypto fixtures remain unchanged. The PR is
marked breaking. No legacy decoder or `v2` crypto branch is added.

## Verification contract

- Unit tests authenticate origin and reject missing/unknown values and tampering;
  frozen personal/cache vectors open; password replacement retains both key kinds
  and the stable root used by remembered unlock.
- OIDC tests prove zero prelogin calls and no synthesized account KDF identity on
  shared-only login. Existing password/personal-key proof tests remain required.
- Sync tests deny a local cache key before personal publication, target resolution
  or reconciliation, even for an empty/uninitialized personal vault.
- Real HTTP/Postgres tests cover two shared-only accounts on one server, one device
  password, independent random keys, restart/remembered unlock and identical exports;
  abandoned preparation leaves no bound lost fingerprint; an incompatible fingerprint
  cannot replace the keyring; policy enablement preserves pending data and readable
  exports while returning the typed enrollment refusal. Explicit personal-key
  enrollment and source-scoped import into a new root preserve that account's
  pending items without copying the other account.
- Existing SQLite CAS, snapshot/restore, crypto golden, native/FFI and shared-flow
  tests plus architecture and audit dependency gates cover the reused boundaries.

## System alignment review

- **Reuse:** the existing account envelope, device root, verified crypto, keyring
  metadata CAS, Config lease, shared unlock routing and sync catalog/key-proof owner.
- **Justified divergence:** `LocalCacheKey` represents only local cache custody;
  `AccountPassword` also authorizes personal E2EE. Authenticated purpose prevents
  the two from being treated as interchangeable.
- **Realign now:** external session KDF requests, per-profile account labels,
  enrollment, sync/import and frozen account-envelope fixtures consume this purpose.
  JSON import adds explicit source selection; proposed ADR 0015's export scope
  remains separate.
  The old unconditional account-KDF requirement is removed.
- **Aligned as-is:** thin COSMIC/Apple adapters, offline device unlock, remembered
  root wrapping and snapshots. Server shared encryption stays server-owned; no
  device/cache/personal key is sent to the server.
- **Outside this decision:** a future in-place cache-key transition would need its
  own lossless Config/SQLite publication design. Current behavior is an explicit,
  tested refusal with export/import; no automatic transition is promised.

## Values interrogation and operational cost

There is no separate values manifest or ADR template. These tests apply the
trust, custody, SSoT, crash-safety and bounded-work rules in [AGENTS.md](../../AGENTS.md).

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Authenticated enrollment policy | Verified capability selects purpose; missing data grants nothing | One app result; existing native activation path | Reauthorize and retain exact profile lease through CAS | Enrollment adds bounded authorization/catalog reads; offline unlock adds none; test absent KDF and second account |
| Origin in account AAD | A cache key cannot gain personal authority by relabeling | Extend existing envelope, no new bag | Strict bounded decode, verified wrap and CAS | One intentional Pre-GA export/import; frozen vectors and substitution tests |
| Durable random-key publication | Config cannot pin a lost random candidate | Reuse keyring and normal sync binding | Keyring CAS precedes Config fingerprint; preparation is repeatable | No new journal/recovery command; test abandoned preparation and retry |
| Existing-cache and policy-change refusal | Preserve keys and pending plaintext access | Existing proof/fingerprint owner remains canonical | Refuse before personal publication or cache mutation | Manual export/reconnect/import costs O(cache size); tested refusal is preferred to an unverified cross-file rekey |
| JSON import source scope | No implicit cross-account plaintext transfer | Existing streaming importer, explicit file UUID | Validate source before server/SQLite mutation; bounded scan | One caller argument, no new UI or exporter; two-account selective round-trip test |
| KDF-independent account label | `/me` name is display only; subject still authorizes | Credential profile owns labels, KDF record retains KDF provenance | Bounded metadata; no credential read for account lists | No extra request or shell name inference; two-account label assertions |

No new crate, table, endpoint or central registry is introduced. Independent
changes can use existing capability submodules and tests; no new global authoring
lock or manifest edit is needed. The multi-step one-time export/import cost is
limited to this intentional Pre-GA format change or an explicit personal-policy
transition; ordinary enrollment, unlock and sync remain idempotent operations.

## Alternatives rejected

- Reusing login/device passwords or prompting for an invented shared-only password:
  adds a secret/KDF with no personal E2EE role and conflates independent boundaries.
- Generating keys on every login or automatically changing origin: strands existing
  caches or silently grants personal authority to a device-local key.
- Re-encrypting existing caches in place in this change: requires a separate
  cross-file key/fingerprint transition and broad pending/history rewrite. The
  explicit export/import path provides verifiable lossless item-data transfer now.
- A second keyring, shell-specific key generation or a new v2 crypto envelope:
  duplicates canonical custody or adds compatibility debt during Pre-GA.
