# ADR 0018: Passkey account access and independent recovery

- **Status:** Proposed
- **Proposed:** 2026-11-16
- **Scope:** server authentication, native account-key custody, Connect/unlock and recovery
- **Related:** [#30](https://github.com/constXife/zann/issues/30),
  [ADR 0006](0006-passkey-provider.md) (Proposed; Zann as a provider),
  [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0012](0012-shared-only-account-cache-keys.md) (Accepted),
  [ADR 0013](0013-account-key-rotation.md) (Proposed),
  [ADR 0017](0017-portable-encrypted-backups.md) (Accepted),
  [#149](https://github.com/constXife/zann/issues/149) (historical portable-unlock discussion)

The product direction below is confirmed; this ADR remains Proposed pending
protocol review, provider qualification and the server-access recovery decision.
It is not an implemented protocol or approval to change cryptographic formats.
The repository has no separate values manifest; governing values are the trust
separation, custody, canonical ownership, atomicity and bounded-work invariants
in [AGENTS.md](../../AGENTS.md).

## Context and measured baseline

Inspected `main` at `7ec8e0798d4948b44c31ff1a045cc15276d70528`:

- [Authentication routes](../../crates/zann-server/src/domains/auth/http/v1/mod.rs)
  support passwords, OIDC and service accounts; there is no WebAuthn RP flow.
  [Session helpers](../../crates/zann-server/src/domains/auth/helpers.rs) already
  issue device-bound access/refresh sessions. Passkey login must reuse them.
- [Account enrollment](../../crates/zann-client/src/app/account_keys/enrollment.rs)
  associates personal vaults with a password-derived account key; shared-only
  accounts receive a random local cache key. These are distinct purposes.
  [Sync proof](../../crates/zann-client/src/sync/account_key.rs) checks published
  personal vault keys before binding an account-key fingerprint.
- [Device unlock](../../crates/zann-client/src/app/unlock.rs) uses an independent
  local password and stable random root. The root wraps multiple account keys.
  [Account envelopes](../../crates/zann-client/src/app/unlock/accounts.rs) bind
  device, storage, server, subject and key origin; insertion refuses replacement.
- The [existing recovery-kit service](../../crates/zann-server/src/domains/users/service.rs)
  generates a secret on the server and stores its password-style hash. It does
  not wrap a personal account key; its existence does not establish E2EE recovery
  or a complete lost-passkey server-login recovery flow.
- [#291](https://github.com/constXife/zann/issues/291) concerns passkeys for other
  sites. The current desktop provider (#293/#305) supplies presence, not UV or
  PRF. Neither it nor device-local hardware unlock implements this proposal.
- ADR 0013 records rotation requirements, not an available rotation protocol.
  ADR 0017 archives recover data, not online account authorization.

## Confirmed product direction

1. **Account Encryption Password remains the default independent text root.**
   It derives the personal account key through the existing Argon2id owner on a
   fresh device. Passkey enrollment adds another wrapping method; it does not
   remove the password or require rotation to a random account key. A future
   long random printed Recovery Key can replace this text root only through a
   separately reviewed transition. A recovery root must always remain available.
2. **Choose the passkey mode at enrollment.** Offer `Auth + Vault Unlock` by
   default when PRF is proven usable, and `Auth-only` when PRF is unsupported or
   the user disables vault unlock. Both authenticate to the server; only the
   former has an account-key grant. No grant is inferred from a credential name.
3. **Full unlock requires user verification.** A touch-only hardware operation
   cannot release the server-held account-key envelope. Require UV in registration
   and authentication, enforced by RP verification, not by a caller-supplied flag.
   Auth-only registration follows an explicit server authentication policy;
   missing PRF alone must not reject an otherwise admitted credential or weaken
   that policy. Full-unlock requirements never silently downgrade.
4. **New-device experience:** server URL -> passkey/security-key ceremony ->
   session and, for full-unlock credentials, local account-key unwrap -> configure
   local device protection -> verified keyring enrollment and first sync. For
   Auth-only, ask for the Account Encryption Password before local enrollment.
5. **A bootstrap factor must be available before Zann unlock.** Hardware keys,
   an external provider or a qualified phone-assisted ceremony are candidates.
   Passkeys stored solely inside locked Zann cannot bootstrap it. Current Zann
   provider UV/PRF limitations also prevent claiming self-hosted full unlock.

## Proposed technical decision

### 1. Keep login, account encryption and device protection separate

WebAuthn creates an ordinary server session. It does not itself produce an account
key. The Account Encryption Password or a verified PRF grant supplies that key
locally. DeviceUnlock independently protects the multi-account root and cache.
Neither the account password nor PRF output is sent as a server login password.

On a new device, hold a recovered account key only in a bounded, cancellable,
account-bound bootstrap operation until local protection is configured. Do not
persist a usable unprotected SQLite cache or recreate a second keyring. Enroll
through the existing proven keyring CAS, account fingerprint and sync proof.
An existing locked root still needs its local factor: one account's passkey must
not unwrap the root or expose other accounts. A general root-less vault session
is not required by this onboarding proposal.

Passkey auth returns the account's authenticated KDF identity for the text-root
path. Do not invent a salt, derive an account key from an empty password, or
interpret the authentication method as the encryption-key purpose. Shared-only
accounts retain ADR 0012's random local cache-key policy.

### 2. Standard RP authentication and explicit deployment identity

The server auth domain owns registration, discoverable authentication, credential
management and bounded challenge state. Verify challenge, type, RP hash, exact
allowed origin, user handle/account binding, signature, the selected UV policy
and active credential/account state. Full unlock always requires UV; pin down the
Auth-only UV policy before acceptance. Reuse ordinary device/session issuance in
the same successful challenge-consumption transaction. Use a maintained WebAuthn verifier, not the
provider-side `zann-passkey` signer. Evaluate
[webauthn-rs](https://docs.rs/webauthn-rs/latest/webauthn_rs/) in the spike; exact
library/features remain a review decision.

Configure RP ID and exact browser/extension/native origins as deployment identity,
never infer them from Host headers or page input. RP IDs lack ports; independent
deployments sharing a domain need explicit policy. RP/domain changes require
credential re-enrollment. Preserve exact endpoint, server identity and fingerprint
checks before proofs are sent; email is a discovery hint, not account authority.

Apply standard counter/backup verification: syncable credentials can use zero
counters, and backup state does not prove an independent recovery copy. Synced
devices share a credential and cannot be individually revoked at the RP. See
[WebAuthn credential backup state](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup).

### 3. One independently verified account-key grant per full-unlock credential

A grant wraps the current account key under a credential-specific PRF-derived
wrapping key. The server stores the public credential and opaque grant; it never
receives the PRF result, wrapping key or personal account key. Public credential
IDs and authentication signatures are not encryption key material.

`zann-crypto` owns the reviewed derivation and ChaCha20-Poly1305 wrap. Bind the
wrapping transcript/AAD to server identity, canonical subject, RP ID, credential
ID, grant ID, purpose and account-key epoch. Trial-decrypt and compare every new
wrap before publication. A full-unlock credential must prove actual PRF output;
registration support flags alone are insufficient.

The target login is one discoverable assertion, including PRF evaluation. Use a
stable, public, versioned PRF input derived from the already trusted deployment/RP
and unlock purpose; standard `eval` can apply to whichever credential is selected.
After server verification identifies the subject and returns the matching grant,
derive the wrapping key using that grant's complete bound context. Account/epoch
binding belongs in this wrapping derivation and AAD; do not require an unknown
credential-specific input before discoverable selection. Specify the exact input
encoding/key schedule and qualify it on real providers before acceptance. Native
CTAP hmac-secret must match WebAuthn PRF's input normalization and UV-dependent
secret semantics; do not treat raw inputs/outputs as interchangeable by name.

The [PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) is optional;
outputs can be absent at creation. Enrollment can require an additional assertion
before enabling full unlock. A provider combination that cannot achieve the
one-ceremony login target is not advertised as supporting that experience.
Never send whole browser credential JSON to the server: `toJSON()` can include
PRF results. Construct an allowlisted authentication DTO instead.

Expected unsupported PRF yields the explicitly authorized Auth-only path and a
clear Account Encryption Password prompt. If an enrolled full-unlock grant is
missing, corrupt or fails verification, retain that diagnostic and offer explicit
password unlock; never silently reset the key, overwrite the grant, or disguise
corruption as ordinary unsupported capability. Cancellation aborts the operation.

### 4. Trusted adapters, not server-served personal-key JavaScript

Personal key handling stays in trusted installed client code. A server web page
may perform login-only WebAuthn, but must not request the vault PRF, handle the
Account Encryption Password/recovery secret or receive an account key.

For COSMIC, investigate a private packaged extension-origin page invoking native
browser WebAuthn, with an effective host grant for the RP and exact extension
origin allowed at the server. Chromium checks effective
[extension RP host permissions](https://chromium.googlesource.com/chromium/src/+/ecf43dd2aa505fc586380559884f304e1846c32d/chrome/browser/webauthn/chrome_web_authentication_delegate.cc).
This is a feasibility direction, not qualified Zann support. It needs locked-vault
pairing through existing native management, the authenticated Noise channel,
strict sender/operation binding and a non-embeddable extension page. No website
injected shim, global proxy or arbitrary-page secret-return IPC endpoint.

Apple uses a native AuthenticationServices adapter; its
[PRF APIs](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput-c.class)
provide a candidate. Android needs an independently qualified adapter. Record
associated-domain requirements, exact OS/browser/provider/firmware versions and
phone/hybrid PRF behavior. App minimum versions and brand names do not prove
support. Qualify sync to a clean device and successful unwrap, not only local
feature detection; provide explicit Auth-only support where PRF is unavailable.

### 5. Independent recovery has two separate jobs

**Recover decryption:** the Account Encryption Password remains the first-release
text root. In Auth-only mode it derives the account key locally using authenticated
KDF parameters and existing personal-vault proof. Losing every passkey must not
force a change of this encryption key or destroy readable local copies.

**Recover server authorization:** possession of the encryption password alone
does not currently issue a server session. Before shipping a lost-all-passkeys
claim, select and test an independent authorization path:

- Retain a separate server password or deploy an explicit OIDC/admin recovery
  policy, then locally unlock with the Account Encryption Password; or
- Specify a client-generated independent Recovery Key with separate public
  recovery-proof and key-wrapping purposes, enabling self-service server and
  personal-data recovery. Never send its raw secret to the server.

This product choice is still open. Do not silently reuse the encryption password
as a server credential or advertise today's server-generated recovery kit as
sufficient. Any future text-root replacement must be generated locally, saved
outside Zann/the passkey provider and proven before removing the prior root.
Its exact proof transcript, key schedule and replacement transaction need review.

An already unlocked device can authorize enrollment of a tested replacement
passkey using fresh server authorization plus current account-key custody. A
stolen session alone must not replace the accepted personal-key manifest, remove
the text-root recovery path or add a usable decrypting grant. Specify the
manifest/custody proof; local unwrap alone is not server-verifiable custody proof.
Bind generation and purpose to prevent substitution and cross-account replay.
A fresh device cannot detect every malicious-server rollback without an independent
checkpoint; document that limit rather than claim global rollback prevention.

If no text root, usable grant, unlocked copy or independent backup survives,
personal data is unrecoverable. Admin/email/OIDC reset cannot decrypt personal
vaults. Shared-vault authorization recovery remains server-policy controlled.
ADR 0017 backup restore recovers data, not an online login session.

### 6. Revoke factors without overstating rotation guarantees

Revocation atomically disables that credential's login and deletes its unlock
grant, leaving other credentials and configured devices usable. Retrying a
completed revocation is idempotent. It stops future server access, not already
copied keys or offline plaintext; devices sharing one synced credential revoke
together. Session handling and explicit revoke-existing-sessions options must
have tested semantics.

Initial enrollment wraps the existing account key; ADR 0013 rotation is not a
prerequisite. Password change, account-key rotation and suspected compromise are
separate operations. Before implementing them, specify epochs, unavailable
factors' grant renewal, readable caches, pending writes and history under ADR
0013. Updating a password-derived key cannot magically rewrap grants whose PRF
is unavailable. Rewrapping the account key alone also does not revoke previously
learned vault keys; compromise can require vault-key rotation/re-encryption.

Retaining the password-derived root retains its offline password-guess exposure.
That is an explicit cost of the confirmed recovery model, not a claim that adding
passkeys makes the account cryptographically passwordless. Do not introduce
random-root conversion or a new envelope version as part of initial enrollment.
Any later serialized origin/AAD change invokes ADR 0009's breaking-change,
golden-fixture and lossless export/import gates.

## State, ownership and resource contract

Flow: prepare -> trusted ceremony -> verify -> trial unwrap -> expected-generation
publication -> read-back -> device protection/enrollment -> first sync. Auth-only
substitutes explicit local password derivation/proof for PRF unwrap. Enrollment
of a grant requires fresh authorization and current key custody. A new account's
text-root setup must be complete before personal-vault initialization.

There is no cross-network/SQLite atomic transaction. Reuse secret-free operation
intent, exact generation leases, keyring CAS and remote read-back reconciliation.
Retain old readable state until replacement is proven; never blindly replay an
ambiguous authentication/grant commit or persist secrets in an intent record.

Proposed limits: 16 active WebAuthn credentials per account, one unlock grant per
full-unlock credential, 120-second single-use challenges, four pending challenges
per known account/client binding, 64 KiB finish messages and 128 KiB manifests.
Explicit global/anonymous admission quotas, cleanup budgets and provisional-account
expiry remain acceptance requirements; per-account caps alone are insufficient.
No all-account scans or repeated provider prompts for discovery.

- `zann-server::domains::auth`: RP verification, challenge/credential/grant
  transactions, server recovery policy and ordinary session issuance.
- `zann-core::api`: typed public contracts; `zann-crypto`: secret types, derivation,
  authenticated wraps and any reviewed custody/recovery proof primitives.
- `zann-client::app` / auth/session/config/sync: one orchestration owner for trust,
  encryption methods, epochs and crash reconciliation. Preserve auth -> credentials
  -> config lock order; no network/OS I/O under a config lock.
- `zann-client-sqlite::local_vault`: bootstrap custody, device protection, proven
  keyring CAS and cache preservation. No parallel key database.
- `zann-keystore` and thin browser/native adapters: provider capability/results.
  `zann-flows` owns shared state/projections; FFI projects them. Shells contain
  UI/OS/browser calls, not encryption or recovery policy.

## System alignment and per-mechanism values review

- **RP auth — align on implementation:** reuse session/trust owners; keep personal
  secrets out of login; atomically consume challenges with session issuance under
  expiry/message/admission bounds. Factor auth service responsibilities before
  growing them. Cost: verifier dependency/storage. Test replay, origin/RP/UV,
  account binding, backup/counters and racing finish.
- **Modes and grants — align on implementation:** preserve the current password
  key purpose and add explicit per-credential unlock capability. One crypto owner,
  local PRF custody, verified wraps before generation CAS and bounded grant count.
  Cost: password-guess exposure remains and unsupported providers require the
  authorized password prompt. Test full/Auth-only, disabled unlock, corrupt grant,
  wrong context/epoch and no silent downgrade after cancellation.
- **Adapters — align on implementation:** one injected port serves installed
  clients; never delegate personal-key custody to pages. Operation binding rejects
  stale completion, one ceremony at a time with expiry. Cost: packaging/domain
  association and provider qualification. Test forged senders, locked pairing,
  cancellation and secret-free network DTOs.
- **Bootstrap/device — aligned boundary, extend orchestration:** reuse independent
  DeviceUnlock and verified account CAS. Zeroize abandoned account keys, persist
  no unprotected cache, retain generation checks and paged queries. Cost: one final
  local-protection step. Test fresh setup/restart and account A never opening B.
- **Recovery — preserve text-root custody; decision pending:** reuse password KDF
  and vault-key proof for decryption, choose server authorization independently.
  Reuse auth owners and atomic credential transitions, with bounded recovery
  challenges. Cost: separate server-recovery availability. If replacing legacy
  recovery semantics, migrate all callers/storage in place; no dual-write or
  misleading E2EE recovery surface. #149's grant need shares this owner, not a
  separate hardware-key table. All-key-loss tests gate completion.
- **Revocation/rotation — reuse and defer precisely:** atomic factor/grant removal
  cannot erase copied secrets. One generation/rotation owner preserves old cache
  and history in bounded batches. Cost: unavailable factors need renewal and
  compromise may need re-encryption. ADR 0013 blocks rotation, not initial grants;
  fault traces and an unaffected second account discriminate the implementation.
- **Backups — aligned as-is:** retain ADR 0017's independent custody, archive owner,
  atomic/private output and bounded frames. Reuse crypto primitives, not archive
  headers as an online protocol. Cost: an independent recovery copy to maintain.

## Delivery and acceptance gates

1. Qualify trusted COSMIC/bootstrap and a real synced PRF credential on a clean
   device, including UV and the one-ceremony login target. Record exact versions,
   permissions/prompts and Auth-only behavior. Qualify native platforms separately.
2. Decide lost-all-passkeys server authorization; review grant/manifest/custody
   transcripts, PRF input/key schedule, recovery/last-factor policy, scoped bootstrap
   states, quotas, expiry, rollback limits and each crash point. These block ADR
   acceptance, not merely final release testing.
3. Deliver RP login through existing sessions and shared flows, including the
   explicit credential mode. Login-only is an intermediate milestone, not #30 done.
4. Deliver tested PRF grants, Auth-only local password unlock, fresh device
   protection/enrollment, revocation and both independent recovery jobs. Require
   clean-device success, unsupported PRF, wrong UV/context, races, cancellation,
   restart/lost responses and unaffected-account evidence.
5. Design rotation/password changes separately under ADR 0013; do not make initial
   passkey enrollment depend on random-root conversion. Coalesce obsolete recovery
   paths only where the selected protocol replaces their actual purpose.

Implementation is T2: update capability/architecture/audit contracts with code;
run format, affected clippy/tests, architecture and crypto-dependency gates plus
security/consolidation review and platform builds. Real provider sync/PRF evidence
supplements fake-port tests. This documentation proposal is T0 and changes no live
auth, encryption, account or local-root state.
