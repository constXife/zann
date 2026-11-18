# ADR 0018: Passkey account access and independent recovery

- **Status:** Accepted — Linux/COSMIC + Chromium internal-account vertical flow; other native provider edges remain scoped follow-up
- **Proposed:** 2026-11-16
- **Protocol specified:** 2026-11-16
- **Accepted:** 2026-11-16
- **Scope:** server authentication, native account-key custody, Connect/unlock and recovery
- **Normative contracts:** [consume/resume](../architecture/passkey-recovery.md),
  [account-key grants and custody](../architecture/passkey-account-keys.md)
- **Related:** [#30](https://github.com/constXife/zann/issues/30),
  [ADR 0006](0006-passkey-provider.md) (Proposed; Zann as a provider),
  [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0012](0012-shared-only-account-cache-keys.md) (Accepted),
  [ADR 0013](0013-account-key-rotation.md) (Proposed),
  [ADR 0017](0017-portable-encrypted-backups.md) (Accepted),
  [#149](https://github.com/constXife/zann/issues/149) (portable-unlock discussion)

This records concrete protocol decisions for review and implementation. It does
not claim deployed auth support, audited cryptography or qualified providers.
No product choice or consume/resume mechanism remains deliberately unspecified.
Platform evidence and implementation tests below gate delivery, not the choice
of a protocol. Status remains Proposed until the documentation review is accepted.

## Context and measured baseline

Inspected source based on `main` at `7ec8e0798d4948b44c31ff1a045cc15276d70528`:

- [Auth routes](../../crates/zann-server/src/domains/auth/http/v1/mod.rs) have
  password/OIDC/service-account flows and no WebAuthn RP. Existing
  [session helpers](../../crates/zann-server/src/domains/auth/helpers.rs) issue
  device-bound tokens; [middleware](../../crates/zann-server/src/domains/auth/core/middleware.rs)
  also admits OIDC JWTs and machine tokens separately. Deleting user sessions
  alone cannot revoke IdP or machine authority.
- [Enrollment](../../crates/zann-client/src/app/account_keys/enrollment.rs) and
  [sync proof](../../crates/zann-client/src/sync/account_key.rs) distinguish
  password-derived personal keys from random shared-only cache keys. Personal
  keys prove published vault-key decryption before fingerprint binding.
- [DeviceUnlock](../../crates/zann-client/src/app/unlock.rs) has its own password
  and stable multi-account root. Account passkeys must not unlock that root.
  [CredentialStore](../../crates/zann-client/src/config/v2/credential_model.rs)
  provides durable put/get/delete separately from local-vault unlock.
- [Recovery-kit issuance](../../crates/zann-server/src/domains/users/service.rs)
  already generates 48 random alphanumeric characters and hashes them through
  canonical KDF/password-pepper primitives. The
  [server schema](../../crates/zann-server/migrations/0001_init.sql) stores
  `users.recovery_key_hash`. Current password-hash/Internal-source checks do not
  cover password-free passkey accounts. There is no consuming recovery endpoint.
- [#291](https://github.com/constXife/zann/issues/291) is Zann as provider for other
  sites. #293/#305 provides presence, not UV/PRF, and cannot bootstrap locked Zann.
  ADR 0013 specifies rotation requirements, not an available rotation protocol.

The repository has no separate values manifest. This decision applies AGENTS.md's
trust separation, secret custody, canonical ownership, crash-safety and bounded
work independently to each mechanism below.

## Decision

### Three independent authorities

Server login issues ordinary account sessions. The Account Encryption Password
or a full passkey grant supplies the personal account key locally. Independent
DeviceUnlock protects the device root/cache. A new-device account-key bootstrap
is bounded, cancellable and memory-only until local protection and proven keyring
CAS complete. An existing locked root still needs its local factor; account A's
passkey never unlocks account B. Shared-only cache-key policy stays ADR 0012.

The Account Encryption Password remains the default independent text root,
using existing authenticated KDF identity and Argon2id. Initial passkey enrollment
wraps the existing account key; it does not require random-root conversion or
ADR 0013 rotation. Retaining this root retains offline password-guess exposure.
A future E2EE Recovery Key is a separate decision, not the Server Recovery Key.

### Explicit credential modes and RP policy

Offer `Auth + Vault Unlock` when actual PRF output and wrap usability are proven;
otherwise, or at the user's choice, offer `Auth-only` followed by local Account
Encryption Password entry. Both modes require UV and discoverable credentials.
Auth-only means missing PRF, not presence-only login; UP-only MFA is outside #30.
Missing UV rejects registration/login, never silently chooses a weaker mode.

Select `webauthn-rs` and its core verifier, with a private adapter in server auth
for required options and discoverable verification. Challenge state stays on the
server; exact RP/origin configuration, credential/subject, type, signature, UV,
backup/counter and revocation checks are mandatory. No page-supplied Host/origin
or zero-counter clone heuristic substitutes for standard verification. The
initial algorithm allowlist is ES256 (-7), consistent across both modes.

The full-mode login target is one discoverable assertion using a public,
deployment/RP-scoped PRF input; wrapping derivation binds the subsequently
verified subject, credential, grant and key epoch. Native CTAP adapters apply
standard WebAuthn PRF normalization exactly once. Crypto transcripts, AAD,
verified wrapping and Ed25519 custody proofs are fixed in the key contract.
The server never receives PRF output, account keys or encryption passwords.

### Authenticated grants without a second key store

One immutable account-key descriptor anchors a public custody verifier. A new
account commits it with first personal-vault initialization; an existing account
requires local vault proof plus fresh interactive authentication bound to the
proposed descriptor. A bearer/refresh session alone cannot bootstrap/replace it.
This is an explicit trust boundary, not a server proof of opaque decryption.

Full grants carry independently signed context/envelopes and fresh mutation
proofs; account revision CAS prevents replayed writes. The server can remove a
grant without a personal key but cannot forge an accepted new grant. The set is
not a globally signed complete roster. Existing local key/epoch bindings detect
more rollback than a clean device; malicious-server omission/rollback is an
explicit residual limit. Decryption failure never means implicit rotation.

Use existing `zann-crypto` verified blob writers, `AppClient` key proof,
Config intents/credentials and SQLite keyring CAS. Keep serialized key purpose
independent from WebAuthn auth method. Any existing envelope/KDF/AAD byte change
must obey ADR 0009, including breaking notes, lossless export/import and fixtures.

### Two recovery locks and three server tiers

First restore server authorization; then decrypt personal data locally using
the Account Encryption Password. Server recovery never changes this password,
account KDF identity, key epoch or personal ciphertext.

1. **Server Recovery Key:** mandatory independently saved one-use code before
   server-password login is disabled/omitted. Reuse the current generator,
   peppered verifier and column through one canonical service, removing accidental
   password-hash-only eligibility. Internal account status/auth-mode checks remain.
2. **Surviving device:** usable refresh plus fresh unlocked-account custody can
   replace a lost factor without consuming the code or requiring that lost factor
   as the only step-up. Full grants still require actual key custody.
3. **Break-glass:** OIDC recovers at the IdP; Internal uses local
   `zann-server admin reset-recovery-key --email ... --out <new-private-file>`.
   Reset rotates server code, revokes old local factors/grants and interactive
   sessions, and supersedes recovery; it cannot decrypt personal data. The new
   owner-only (`0600`, create-new) file is the only credential-delivery boundary:
   never code-in-argv, terminal output, logs or error text.

A Server Recovery Key is a server credential, not an E2EE recipient. It can
ultimately confer eligible shared-server rights and obtain ciphertext for offline
password attacks. It must not be advertised as universally ciphertext-only.
If all personal text roots/grants/unlocked copies/backups are lost, personal data
is unrecoverable even for the administrator.

### Consume/resume, completed without token-reply escrow

Before consumption the client independently saves/re-enters its successor code,
then durably stores it and a random 256-bit resume token through CredentialStore, verifies
read-back, then writes a secret-free operation intent. The successor uses the
shared 48-character generator; moving generation client-side for this transition
ensures its secret survives a lost response. Initial server issuance/admin reset
can still generate codes server-side through the same owner. No plaintext-file
substitute exists if pre-unlock OS credential storage is unavailable.

`POST /v1/auth/recover` consumes the old code once under an immutable operation
ID/body and resume proof. A single user-row/epoch transaction burns it, installs
the saved successor verifier, revokes old passkeys/grants/interactive sessions
and creates a restricted operation. The server stores only resume/code verifiers,
not plaintext codes or token replies.
Authenticated GET status and exact mutation receipts resume that operation;
repeating a consumed code never creates another authority. Ordinary session
issuers, refresh and protected mutations check current account epoch/state.

Replacement registration and a tested UV assertion precede completion; full
mode additionally requires its custody-signed, trial-unwrapped grant. Complete
atomically activates the credential/grant, confirms the unchanged successor
code version and returns only a receipt. A fresh ordinary
passkey login then issues tokens via existing intent machinery. This adds one
assertion in rare recovery and removes the need for secret-bearing reply caches.

Lifetime is 24 hours, status receipts seven days. Expiry/abandon/reset cannot
resurrect burned codes or revoked factors. Losing the OS resume bundle after
consumption requires a new restricted consume using the saved successor code,
or tier-3 authority if it too is lost; old paper code is not a
hidden fallback. All exact states, routes, lock order, retry/error semantics,
quotas and fault cases are specified in the consume/resume contract.

## Ownership and system alignment

- **Auth/session — realign on implementation:** reuse current session issuance,
  recovery verifier and token hash. Add account epochs and one recovery service
  shared by user issuance, consume/resume and local provisioning. Direct OIDC and
  machine authority stay explicit; no new admin/auth framework.
- **Crypto/key custody — realign on implementation:** extend `zann-crypto` with
  typed account transcripts and shared random-code generation; extract reusable
  Ed25519 primitives from IPC without reusing IPC identities. `zann-core::api`
  owns strict public DTOs. Signed grants are justified divergence from unsigned
  device-local wraps because authorization crosses a server boundary.
- **Client/config/local store — realign on implementation:** one `AppClient`
  orchestration owner extends existing intent/credential machinery with recovery
  purpose/operation records. Reuse SQLite proven enrollment and generation leases.
  Resume authority differs from a normal session: bounded recovery router only,
  never normal Bearer token selection or a second key database.
- **Presentation/adapters — align through existing owners:** `zann-flows` owns
  shared phase/choice/error projections; FFI is projection only. Keystore/native
  adapters and installed extension code supply ceremonies/secrets, not auth/KDF
  policy. A private extension-origin page with exact RP host/origin permission
  and paired Noise is the COSMIC path; server-served pages are login-only.
- **Rotation — deferred precisely:** ADR 0013 still owns password/key changes,
  unavailable-factor grant renewal, cache/history/pending-write preservation and
  compromise re-encryption. This is not a blocker for grants over the current key.
- **Backups — aligned as-is:** ADR 0017 keeps independent archive custody and
  bounded restore; archives do not mint sessions or become online grant formats.

## Per-mechanism values and costs

- **UV modes/RP:** personal secrets stay local; one verifier/session owner and
  single-use challenge CAS enforce trust/atomicity under bounded options/expiry.
  Cost: presence-only keys are excluded. Test missing UV, forged origin, replay,
  counter/backup behavior and explicit unsupported PRF.
- **PRF/custody grants:** one crypto/account owner, full bound transcripts and
  decrypt-before-commit protect custody and correctness; fixed record/credential
  limits bound work. Cost: descriptor bootstrap trust and an additional offline
  password oracle, not global rollback prevention. Test context substitution,
  stolen bearer bootstrap, grant replay, wrong key/epoch and local cache proof.
- **Resume bundle/idempotency:** OS-keystore custody plus secret-free atomic
  intents preserve restart safety; primary status/revision receipts make exact
  retries safe without general retry fallback. Bounded lifetime/receipts limit
  authority and storage. Cost: unavailable OS secrets stop dispatch/resume;
  bundle loss requires new consume using the saved successor, or break-glass
  if that independent copy is also lost. Test pre/post-commit crash and racing client.
- **Completion/next code:** candidate generation and verified storage precede
  destructive work; atomic activation reuses auth owners with no token escrow.
  Limits prevent endless staged candidates. Cost: code-save confirmation and one
  additional post-recovery assertion. Test dropped completion/login responses.
- **Revocation/reset:** one auth epoch invalidates interactive authority atomically
  without unbounded deletes; retained local/offline data and independent machine
  policy remain honest. Quotas and fixed cleanup pages bound work. Cost: already
  copied keys/IdP tokens cannot be recalled. Test refresh/reset/consume races.
- **Scope/device separation:** reuse DeviceUnlock and proven account CAS with
  bounded memory-only bootstrap; A never unlocks B. Cost: final device-protection
  setup. Test cancellation, wrong keyring generation and unaffected-account use.

Rejected alternatives: signatures as encryption keys, server-page personal-key
handling, server-code/E2EE-root conflation, single-use burn without durable resume,
replaying token replies, root-wide passkey unlock, and mandatory random-root
rotation for initial enrollment. A recovery-specific signature/key exchange would
add crypto and challenge round trips without improving the existing trusted-TLS
bearer model; a distinct random resume token reuses the canonical token owner.

No new global client registry or manual recovery-command family is introduced.
Independent accounts serialize only their security transitions. A short quota
counter on destructive recovery allocation is the documented deployment-wide
exception; it is not a login/read hot-path lock or candidate-development gate.

## Implementation order and evidence gates

1. Strict DTOs/transcripts, account epochs, bounded server recovery store,
   CredentialStore/intents and fault tests; no exposed consuming endpoint until
   epoch checks cover every ordinary issuer/admission path.
2. Selected RP verifier, staged registration/test and both UV modes; custody
   descriptor/bootstrap and verified grants. Fresh-device proof and last-factor
   guards precede password-free accounts.
3. Restricted consume/resume/completion, surviving-device management and one local
   reset command; test all protocol fault traces before enabling recovery UI.
4. Trusted COSMIC extension/bootstrap and qualified native adapters. Record actual
   OS/browser/provider/firmware, stable cross-device PRF, normalization, permission,
   pairing/cancellation, no-PRF creation and full/Auth-only behavior. Advertise
   full unlock only for passing combinations; qualification is a release gate.

Implementation is T2: update capability/architecture/audit contracts with code;
run affected format/clippy/tests, architecture/crypto-dependency checks, security
and consolidation reviews and platform builds. This docs-only change is T0.
The remaining work is implementation/verification, not an undefined recovery
protocol; no live account, encryption or device-root state changes here.
