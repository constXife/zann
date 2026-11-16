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

This is a design proposal, not an implemented protocol or approval to change
cryptographic formats. Product choices and acceptance blockers below remain open.
The repository has no separate values manifest; the governing values are the
trust separation, custody, canonical ownership, atomicity and bounded-work
invariants in [AGENTS.md](../../AGENTS.md).

## Context and measured baseline

Inspected `main` at `7ec8e0798d4948b44c31ff1a045cc15276d70528`:

- [Authentication routes](../../crates/zann-server/src/domains/auth/http/v1/mod.rs)
  support passwords, OIDC and service accounts; there is no WebAuthn RP flow.
  [Session helpers](../../crates/zann-server/src/domains/auth/helpers.rs) already
  issue device-bound access/refresh sessions. Passkey login must reuse them.
- [Account enrollment](../../crates/zann-client/src/app/account_keys/enrollment.rs)
  associates personal vaults with a password-derived account key; shared-only
  accounts receive a random local cache key. These are distinct purposes.
  [Sync proof](../../crates/zann-client/src/sync/account_key.rs) verifies the key
  against published personal vault keys before binding its fingerprint.
- [Device unlock](../../crates/zann-client/src/app/unlock.rs) uses an independent
  local password and stable random root. The root wraps multiple account keys.
  [Account envelopes](../../crates/zann-client/src/app/unlock/accounts.rs) bind
  device, storage, server, subject and key origin; insertion refuses replacement.
- The [existing recovery-kit service](../../crates/zann-server/src/domains/users/service.rs)
  generates a secret on the server and stores its password-style hash. It does
  not wrap a personal account key; it is not E2EE recovery.
- [#291](https://github.com/constXife/zann/issues/291) concerns passkeys **for other
  sites**. The current desktop provider (#293/#305) supplies presence, not UV or
  PRF. Neither it nor device-local hardware unlock implements this proposal.
- ADR 0013 records rotation requirements, not an available rotation protocol.
  ADR 0017 archives recover data, not online account authorization.

## Proposed product contract

The recommended target is a new-device login using an externally available,
syncable passkey, followed by local personal-vault unlock without an account
master password. Initial setup also creates a separate recovery key, saved
outside Zann and outside the same passkey provider.

Two product decisions still require confirmation before acceptance:

1. Whether passkey access must replace the account master password for personal
   decryption, or whether the initial release is login-only. The recommendation
   above is the former; login-only must be named honestly if chosen.
2. Whether an external provider is the bootstrap requirement, or whether Zann
   must also provide its own account passkey. A credential available only inside
   a locked Zann vault is circular. A self-stored additional credential cannot be
   the only bootstrap or recovery method; current provider UV/PRF support is also
   insufficient. Self-hosted bootstrap requires a separate accepted design.

## Proposed decision

### 1. Separate login, account decryption and device unlock

WebAuthn proves possession/verification to the server and creates an ordinary
Zann session. It does not itself reveal a vault key. A native client separately
opens an opaque account-key grant using a PRF result. A local device factor
opens the existing device root. These authorities never imply one another.

For an already enrolled device, current password/OS/hardware unlock remains a
local offline operation. Passkey account access must also have an account-scoped
session: obtaining one account key can expose only that account's replica,
including its eligible cached data. It cannot unlock the device root, other
accounts, root administration or root-wide export. Persisting into the device
keyring requires the existing root capability and verified enrollment CAS.

This requires extending the canonical local-session capability, not a second
vault implementation. Locked-root account sessions, lock/cancel, account removal,
cache policy and pending sync must be specified before enabling this path.
Initial passkey access needs the server grant; offline PRF unlock is not promised.
Shared-only accounts retain ADR 0012's local cache-key policy; WebAuthn login does
not convert a cache key into a personal encryption key.

### 2. Standard RP authentication with explicit deployment identity

The server auth domain owns registration, discoverable authentication, credential
management and short-lived challenge state. Require fresh challenge validation,
UV, correct type, RP hash, exact allowed origin, user handle/account binding,
credential signature and active credential/account state. Use a maintained
WebAuthn verifier, not the provider-side `zann-passkey` signer as a verifier.
Evaluate [webauthn-rs](https://docs.rs/webauthn-rs/latest/webauthn_rs/) in the spike;
library/feature selection is not settled by this ADR.

Configure RP ID and exact browser/extension/native origins as deployment identity,
never infer them from Host headers or page input. RP IDs lack ports; sharing a
domain across independent deployments needs explicit policy. Domain/RP changes
are credential re-enrollment events, not transparent aliases. Preserve the
client's exact endpoint, server identity and fingerprint checks before secrets
or proofs are sent. Email is a display/discovery hint, not account authority.

Syncable credentials can have zero signature counters; verification must follow
the standard's counter and backup rules, rather than require increments. Backup
eligibility/state does not prove an independent recovery copy. A synchronized
credential is one server credential: its devices cannot be revoked separately.
See [WebAuthn credential backup state and counters](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup).

### 3. Random account key with one independently wrapped grant per factor

New passwordless personal accounts use a random account encryption key. Personal
vault keys remain encrypted under that key using the canonical crypto owner.
The server stores only public credential records and opaque grants. Each grant
wraps the same account key under a credential-specific PRF-derived wrapping key.
Public credential IDs and assertion signatures are never encryption key material.

Bind grant AAD and the derivation transcript to the server identity, canonical
account subject, RP ID, credential ID, grant ID, purpose and account-key epoch.
Persist the public PRF input descriptor with the grant; validate its bounded
canonical encoding locally. Domain-separate account wrapping, recovery wrapping
and all signing uses. `zann-crypto` owns the exact reviewed key schedule and
ChaCha20-Poly1305 wrapping; new wraps must trial-decrypt and compare before commit.

The [PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) is optional;
creation can report support without returning output. Probe an assertion and
prove unwrap before marking a credential unlock-capable. Never serialize a whole
browser credential to the server: `toJSON()` can include secret PRF results.
Build an allowlisted authentication DTO and keep PRF output local.

Discoverable login may need two ceremonies: authenticate to identify the account,
then evaluate that credential's PRF using the verified grant context. Optimize
only when identity/context is already bound; do not assume email-less discovery
provides credential-specific inputs in advance. Missing/changed PRF output is an
explicit unsupported or failed-unlock state, never a password fallback or key reset.

Adding a wrap to today's password-derived account key does not remove its offline
password-guess exposure. Existing-account conversion therefore requires ADR
0013's verified rotation to a random key, with readable caches, pending writes
and history preserved. No blind keyring replacement or reconnect-to-delete-data.
Do not claim this conversion is implemented or create a second envelope version
to evade ADR 0009. Changing serialized key origins/AAD invokes its breaking-change,
golden-fixture and lossless export/import requirements.

### 4. Trusted adapters keep PRF material out of server-served pages

Personal key handling remains within trusted installed client code. A server
web page may perform login-only WebAuthn, but must not request the vault PRF,
handle the recovery secret or receive an account key. This preserves the existing
personal-vault/server-console boundary, including under server compromise.

For COSMIC, investigate a packaged extension-origin bootstrap page invoking the
browser's native WebAuthn API, with an effective host grant for the RP and exact
extension origin allowed by the server. Chromium currently checks effective
[extension RP host permissions](https://chromium.googlesource.com/chromium/src/+/ecf43dd2aa505fc586380559884f304e1846c32d/chrome/browser/webauthn/chrome_web_authentication_delegate.cc).
This is a feasibility direction, not qualified Zann support. It needs locked-vault
pairing through existing native management, the authenticated Noise channel,
strict sender/operation binding and a non-embeddable private extension page.
Do not reuse the website-injected provider shim or a global authentication proxy.
No arbitrary page or content script gets a secret-return IPC operation.

Apple uses an OS AuthenticationServices adapter; its
[PRF APIs](https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput-c.class)
provide a native candidate. Android needs an independently qualified OS/provider
adapter. Associated-domain requirements, API/OS floors and provider behavior are
release gates; existing app minimum versions do not imply PRF support. Qualify
actual sync/new-device unwrap, not just feature detection or two local assertions.

### 5. Independent recovery, generated locally

Generate a 256-bit random recovery secret in the trusted native client. The
recovery card contains a version/checksum and non-secret account/server locator
and trust information. Require explicit confirmation that it was saved outside
Zann before passwordless enrollment completes. Never send the raw secret to the
server, log it, place it in URLs/argv or persist plaintext without private modes.

The proposed construction derives separate recovery wrapping and recovery-proof
keys. The server keeps a public challenge-verification key and an opaque wrap of
the account key; it never receives the wrapping key or signing seed. A signed,
single-use challenge yields only a short-lived recovery capability until a new
tested passkey/grant and replacement recovery material are ready. Ed25519 is a
candidate; reuse/extract the crypto primitive owner, not IPC identities/transcripts.
The exact transcript, key schedule and authorization protocol require review
before acceptance; this paragraph is not a bespoke wire specification.

Recovery completion atomically publishes the tested replacement grants, rotates
the recovery verifier and revokes the selected old credentials and sessions under
an expected generation. Account lookup, challenge issuance and wrong proofs must
be enumeration/rate bounded. Acknowledged generation/read-back resolves a lost
response; never blindly repeat an ambiguous recovery commit.

Ordinary enrollment/management also needs current account-key custody and fresh
server authorization. A stolen session alone cannot replace the recovery verifier,
publish an accepted personal-key manifest or remove the last proven recovery path.
Define an authenticated account encryption manifest and generation proof; local
successful unwrap alone is not a server-verifiable custody proof. Prevent grant
substitution, cross-account replay and stale-manifest acceptance. A fresh device
cannot detect every malicious-server rollback without an independent checkpoint;
document that residual limit rather than claiming global rollback prevention.

An unlocked device or independent second factor can enroll a tested replacement.
Without any usable grant, recovery secret or unlocked copy, personal data is
unrecoverable. Admin/email/OIDC account reset cannot decrypt it. Shared-vault
authorization recovery remains server-policy controlled. Backup restore is a
separate disaster-recovery workflow and does not mint a login session.

Revocation stops future server access, not already copied keys or offline data.
Account-key rewrap alone does not revoke previously learned vault keys. Suspected
key compromise needs a separately specified vault-key rotation/re-encryption
scope in ADR 0013; a lost-device action must state its actual guarantees.

## State, ownership and resource contract

The canonical flow is prepare -> trusted ceremony -> verify -> trial unwrap ->
generation-checked publication -> read-back -> local enrollment. Registration of
a new account first holds only a provisional capability: it cannot create a
usable personal vault until both the passkey grant and recovery grant are proven.
There is no cross-network/SQLite atomic transaction: persist secret-free operation
intent and expected generations, reconcile remote outcome, then commit locally.
Retain the old readable state until replacement is proven; bound abandoned
provisional registrations and challenges by expiry and cleanup quotas.

Proposed limits: 16 active WebAuthn credentials per account, one unlock grant per
credential plus one current recovery grant, 120-second single-use challenges,
four pending challenges per known account/client binding, 64 KiB finish messages
and 128 KiB manifests. Add explicit global/anonymous admission quotas and measured
cleanup bounds before shipping; per-account limits alone do not prevent exhaustion.
Do not scan all accounts or invoke providers in a loop to discover a match.

- `zann-server::domains::auth`: RP verification, bounded challenge/credential and
  manifest transactions, scoped recovery authorization; reuse session issuance.
- `zann-core::api`: common typed public contracts; `zann-crypto`: secret types,
  derivation, authenticated wraps and reviewed proof primitives.
- `zann-client::app` / auth/session/config/sync: one orchestration owner for trust,
  custody, account epochs and crash reconciliation. Preserve auth -> credentials
  -> config lock order; no network or OS I/O while holding a config lock.
- `zann-client-sqlite::local_vault`: scoped sessions, proven keyring CAS, cache
  preservation. Extend this owner rather than adding another key database.
- `zann-keystore` and thin browser/native adapters: provider capabilities and
  typed ceremony results. `zann-flows` owns shared state/projections; FFI projects
  them. Shells contain presentation and OS/browser calls, not recovery policy.

## System alignment and per-mechanism values review

- **RP login — align on implementation:** keep personal keys out of auth;
  reuse session/trust owners and atomic single-use challenge consumption with
  session issuance. Apply the message, expiry and admission bounds above;
  factor auth service responsibilities before adding more flows. Cost:
  verifier dependency/challenge storage. Discriminator: wrong origin/RP, replay,
  UV absence, revoked credential, counter/backup and concurrent finish tests.
- **PRF grants — align on implementation:** one account encryption purpose with
  explicit unlock methods, replacing the personal-means-password assumption.
  Custody stays local, trial unwrap precedes CAS, grant counts are bounded. Cost:
  provider compatibility and a possible second prompt; test cross-device unwrap,
  wrong context/epoch, missing PRF and malformed oversized records.
- **Trusted adapters — align on implementation:** only installed code handles
  PRF results; page requests cannot inherit native authority. Provider calls use
  one injected port and operation-bound cancellation, with no secret persistence
  or response after stale completion. One explicit ceremony at a time and expiry
  bound admission. Cost: packaging/associated domains and platform qualification;
  test forged senders, locked-vault pairing, stale results and secret-free DTOs.
- **Scoped unlock — align on implementation:** reuse replica/session ownership
  without releasing the multi-account root. Cost: explicit root capability vs
  account-session capability; preserve existing paged queries and generation
  leases, and avoid cross-account scans or persistent root replacement. Test A unlocked by passkey while B and root-wide
  operations stay locked, including lock/cancel/restart and pending writes.
- **Recovery — realign on implementation:** replace server-generated recovery-kit
  semantics, obsolete hash storage/DTO/UI and all callers together; no dual-write
  or compatibility route. One client-owned recovery grant/proof protocol also
  subsumes #149's future portable-envelope need where its semantics fit. Cost:
  custody proof, anti-lockout and multi-store crash traces; do not treat that
  historical discussion as an accepted protocol or reuse token secrets as PRFs.
  Keep recovery secret client-owned, publication/revocation atomic and expiry,
  grant count, enumeration and global admission bounded as specified above.
- **Rotation — deferred with a hard trigger:** ADR 0013 must specify/verify epoch,
  cache/history and compromise behavior before converting existing accounts.
  Random shared-only cache keys remain isolated; no extra account-key store.
- **Backups — aligned as-is:** ADR 0017 keeps its independent archive semantics.
  Reuse secret handling and trial-decrypt primitives, not archive headers as an
  online account protocol. Recovery cards remain a separate custody obligation.

## Consequences and rejected alternatives

The user can recover a personal account without entrusting decryption keys to
the server, provided an independent recovery copy survives. The cost is provider
dependency, recovery-card custody, scoped-session work and a reviewed publication
protocol. A cloud provider's account recovery becomes part of the passkey trust
boundary; multiple devices in that provider are not independent factors.

Rejected: signatures as encryption keys, personal-key handling in server-served
JavaScript, recovery material generated by the server, opening the multi-account
root with one account credential, silent password fallback, and promising
cryptographic erasure by deleting a credential. The closest existing mechanisms
are reused above; none currently provides a complete remote unlock protocol.

## Delivery and acceptance gates

1. Resolve the two product choices; qualify a trusted COSMIC/browser bootstrap
   with a real externally synced PRF credential on a fresh device. Record exact
   browser/provider/OS versions, permissions and prompt sequence. Qualify Apple
   and Android separately; unsupported platforms remain explicit.
2. Review exact grant/manifest/proof transcripts, trusted origin configuration,
   fresh-device rollback limits, scoped-unlock capability and every crash point.
   Specify recovery save confirmation, last-factor policy, quotas and expiry.
   These block acceptance of this ADR, not just release testing.
3. Deliver RP auth through existing sessions and typed shared flows. Login-only
   is an honest intermediate milestone, not completion of #30. Separate public
   browser login from the trusted PRF path.
4. Deliver random-key enrollment, scoped personal unlock and independent recovery
   together before offering passwordless personal accounts. Prove restart,
   lost-response, racing enrollment/recovery and unaffected-account behavior.
5. Specify/implement ADR 0013 conversion, then remove superseded password-derived
   enrollment/recovery paths in the cutover scope. Preserve unrelated password
   authentication where still explicitly supported; no silent method fallback.

Implementation is T2: update capability/architecture/audit contracts with the
code; run format, affected package clippy/tests, architecture and crypto-dependency
gates plus security/consolidation reviews. Require real provider sync/PRF evidence
and platform builds beyond fake-port tests. This documentation proposal is T0;
it changes no live auth, encryption, account or local-root state.
