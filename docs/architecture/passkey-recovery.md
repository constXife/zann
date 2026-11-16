---
title: Passkey server recovery protocol
description: One-use server recovery, durable resume and generation-checked completion.
---

# Passkey server recovery protocol v1

Normative companion to [ADR 0018](../adr/0018-passkey-account-access.md).
This specifies implementation behavior; it does not claim deployed support.
Personal account-key grants are specified in [the key contract](passkey-account-keys.md).

## Authority and durable state

A Server Recovery Key authorizes server recovery, not personal decryption.
Internal/passkey recovery is disabled in OIDC-only mode and for disabled/deleted
accounts. OIDC recovery uses the IdP, without a local-code bypass. Shared-only
accounts can recover in Auth-only mode without inventing a personal key.

The client prepares three independent values with the shared crypto owner:

- `operation_id`: random UUIDv4, never reused for another attempt/account.
- `resume_token`: 32 CSPRNG bytes, base64url without padding on the wire.
- `next_recovery_key`: 48 uniformly sampled ASCII alphanumeric characters,
  using the same generator as initial server recovery-kit issuance. Move that
  generator to `zann-crypto`; do not duplicate it in native/browser shells.

Replacement generation moves to the trusted client so secrets can be durably
stored **before** destructive consumption. It remains a server authentication
code, not an E2EE key. Initial issuance and local administrator reset can still
produce a server-generated code through the same primitive.

Before consume, independently save and re-enter the successor code. Keep the old
card until consume status is known: only the old code works before commit, only
the successor afterward. Then write one purpose-bound credential bundle containing
`resume_token` and `next_recovery_key` through `CredentialStore`, read it back and
verify exact equality. The account encryption password/key and old recovery code
are never in this bundle. Then atomically persist a secret-free operation intent
with exact endpoint/server pin, locator, operation ID, immutable request context,
credential reference and phase. Private modes and existing Config repository
atomic writers apply. Extend that owner with operation records; do not create a
second credential database or shell journal. At most four pending local operations
are allowed; waiting recovery for A must not lock unrelated account B.

The OS credential store must work before device-vault unlock. If unavailable,
stop before consuming the code: no plaintext-file or ephemeral-only substitution.
Crash before intent publication can leave an unreferenced credential; cleanup
uses exact operation references, never deletes a possibly committed credential.
Local trust changes stop dispatch/resume until the existing explicit trust flow
resolves them; they do not silently rebind this operation to another server.

Server account state adds `auth_epoch`, `security_revision`,
`recovery_key_version` and optional `active_recovery_id`. All are transactionally
owned by the auth domain. A separate recovery row contains operation/account IDs,
resume-token verifier, immutable consume digest, consumed code version, captured
account-key epoch, creation/expiry, state/revision, successor code version,
staged credential/grant and bounded mutation receipts. No plaintext codes,
resume tokens or session tokens are persisted in that row.

Use the existing token hash owner with a domain-separated input
`base64url(T("zann recovery resume v1", operation_id, resume_token))` and the
configured token pepper; compare verifiers in constant time. `T` is defined by
the key contract. Code verification uses the existing bounded user KDF identity
and Argon2id/password-pepper scheme. Changing peppers requires the existing
explicit credential invalidation policy; it is not transparent recovery support.

## State machine

Only these durable transitions exist:

- Absent -> `Consumed`: burn the old code, revoke old interactive authority,
  atomically replace its verifier with the saved successor's and bind resume.
- `Consumed` -> `CredentialReady`: new credential registered and tested with UV;
  a full-mode candidate additionally has a verified, custody-signed grant.
- `CredentialReady` -> `Completed`: activate candidate credential/grant, confirm
  the current successor code and clear recovery-only mode. No tokens are returned.
- Any nonterminal state -> `Expired`, `Abandoned` or `Superseded`: permanently
  invalidate its recovery authority and staged material. Old factors/codes do
  not become usable again. The successor code remains valid to start a new
  restricted operation; absent that code, independent tier-3 authority is needed.

A staged credential never authenticates through ordinary login. `Completed`
receipts are status-only. Cancellation before consume has no remote effect;
after consume it pauses locally by default and can resume until expiry. An
explicit authenticated abandon is destructive and must say that the old code
and credentials will stay invalid. There is no automatic rollback of consumption.

## Endpoints and idempotency

Recovery authority is `Authorization: Recovery <operation_id>.<resume_token>`.
It is accepted only by this allowlisted recovery router, never ordinary Bearer
middleware. TLS trust/pinning and full header/body redaction are mandatory.
Do not use cookies, query tokens, redirects or a server-served JavaScript client.
All responses carry `Cache-Control: no-store`; CORS is not recovery authorization.

The route set is intentionally small:

1. `POST /v1/auth/recover`: consume/start. Body has `operation_id`, `locator`,
   `recovery_key`, `next_recovery_key` and the typed new-device descriptor.
2. `GET /v1/auth/recover/{id}`: authenticated status/resume; returns identity,
   state, revision, expiry, captured key epoch and staged-factor summary, no codes,
   token verifiers, PRF outputs or normal access/refresh tokens.
3. `POST /v1/auth/recover/{id}/credential/options` and `/credential/finish`:
   shared RP registration, test-assertion and full-grant commit flow with
   recovery-scoped admission. `options.phase` is `register`, `test` or `grant`;
   the last issues a custody nonce over an already computed grant-body digest,
   not another WebAuthn ceremony. `finish` has the matching strict phase DTO.
4. `POST /v1/auth/recover/{id}/complete`: activate staged factor, confirm code version.
5. `POST /v1/auth/recover/{id}/abandon`: permanently end the restricted operation.

Personal read-only catalog/ciphertext access is exposed by typed recovery-router
handlers over existing bounded query services, under `/v1/auth/recover/{id}/data`.
It does not enable the ordinary sync router, writes, shared plaintext, deleted
history, admin APIs or service-token creation. Vault ownership/type/cache policy
are checked for every page; no arbitrary item lookup or unbounded export route.
A completed/terminal operation cannot continue reading ciphertext with its token.

Every mutator after consume has a random `mutation_id`, `expected_revision` and
an endpoint-specific strict DTO. Persist the public request and its canonical
digest before dispatch if a response is needed after restart; strip PRF results
first. The server keeps one receipt per bounded mutation ID. Same ID, body and
authority returns its original sanitized result without repeating work; same ID
with different body is `409 mutation_conflict`. Receipt lookup precedes revision
comparison, so a lost response remains resolvable after the revision advanced.
Two distinct mutations with the same revision cannot both commit.

For consume, operation ID is the idempotency key. Same ID and correct resume
proof resolves the existing operation; changing its immutable request digest is
`409 operation_conflict`. A wrong resume proof or another account/locator never
acquires that operation. The digest includes both input codes but is not exposed
or logged; codes are uniformly high entropy. Repeating a completed consume is
status-only and cannot mint credentials, codes or sessions.

This is explicitly idempotent POST behavior, not generic retry permission for
password login or token rotation; see [HTTP retry semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2).
Clients reconcile primary-database status after ambiguity. If no row exists,
they can resend the **same** consume operation/body while the old code remains
in memory, or ask for that code again after restart. They cannot create a new
operation as an automatic retry. An in-flight first request and its retry
serialize on the account row and unique operation ID, producing at most one burn.

## Consume transaction

1. Reject malformed/oversized input and unavailable admission before KDF work.
   Check primary-database operation lookup under resume proof first. Unknown
   account, wrong/used code and ineligible account return the same external
   `401 recovery_rejected`; retain redacted internal causes. No account data or
   operation row is created on failed proof. Rate-limit saturation is `429`.
2. Read the account and current verifier/version; verify the old code and hash
   the proposed successor outside row locks under the existing KDF semaphore.
   Reject identical old/new code, noncanonical format and invalid KDF parameters.
   Unknown accounts use a bounded configured dummy verifier, not random work or
   a different externally documented error. Do not claim perfect timing equality.
3. Start a primary PostgreSQL transaction at Read Committed; lock the user row
   `FOR UPDATE`, then recovery row if present, then quota row. All competing
   recovery, security mutations and session issuers use this lock order. Recheck
   operation receipt under its resume proof before comparing the verified
   snapshot; then eligibility, verifier/version, key epoch and capacity.
   A verified snapshot that changed is rejected, not silently reverified in a loop.
4. Replace `users.recovery_key_hash` with the successor verifier and advance its
   version (old authority is burned atomically), increment `auth_epoch`
   and `security_revision`, delete/revoke all old account passkeys and grants,
   invalidate old interactive sessions by epoch, supersede prior recovery,
   and insert `Consumed` with that successor version and a 24-hour absolute
   expiry. Set `active_recovery_id`. Commit these changes and one secret-free
   audit event together. No destructive effect exists before this commit.
5. Return status only. Response loss changes neither consumption nor resumability.

Exactly one current server recovery verifier remains after every successful
transition. A valid successor can start another consume under a **new** operation
and another independently saved successor, superseding a lost/expired operation.
This uses the same base protocol, not a resume bypass or reuse of a burned code.
One-active-operation capacity counts supersession as replacement; retained-row
capacity must still be reserved before changing authority. Ordinary access remains
blocked until a tested credential completes the current recovery operation.

Epoch checks avoid an unbounded session-delete hot path. All session issuers and
refresh commits must lock/check account epoch and recovery state in their own
transaction, so a session racing consumption is either old and invalidated or
refused. Authorization checks epoch/account status in the same database lookup
as token validation; no process-local revocation cache. Long-lived connections
recheck per message; writes recheck in their mutation transaction. Work already
authorized before the consume commit cannot be recalled from the network.

Direct OIDC JWT admission is an existing separate path: Internal code recovery
cannot revoke an IdP's token. In Hybrid mode, a verified OIDC authority may invoke
the same explicit supersede/reset transition to finish first-lock recovery;
it does not bypass local E2EE or resurrect an old local session. OIDC-only never
enables local codes. Existing service-account tokens are a separate machine
plane, cannot call recovery or read personal vaults, and are not implicitly
rotated by user recovery; compromise handling for them remains explicit.

[PostgreSQL row-lock semantics](https://www.postgresql.org/docs/current/explicit-locking.html#LOCKING-ROWS)
provide serialization; unique constraints/CAS remain mandatory. No network,
provider, OS-keystore or Argon2 work runs while transaction locks are held.

## Replacement factor, code confirmation and completion

Registration requires discoverable credentials, `attestation=none` and UV for
both modes. A following successful UV assertion against the staged public key
proves the replacement works. An unsupported PRF selects explicit Auth-only;
full mode must additionally prove the signed grant as defined in the key contract.
Build that grant locally after the test returned PRF output, then request its
digest-bound custody nonce and finish the grant phase. Never request a proof
over an unknown future grant or send PRF output to obtain the nonce.
Fresh challenge state is server-side, 120 seconds, single-use and bound to
operation, account, expected revision, phase and candidate credential digest.
A receipt replay cannot consume a different challenge. Expired challenges can
be replaced without burning another recovery code; at most one staged credential
and two pending challenges exist per operation.

Errors are strict typed records: malformed input `400`, unsupported configured
auth mode `403` without account detail, failed consume `401 recovery_rejected`,
absent operation or wrong resume proof `404 operation_unavailable`, conflicting
body/revision `409`, authenticated expired/abandoned/superseded state `410`,
rate/capacity refusal `429`/`503`. A known receipt returns its committed result
even when the supplied expected revision is old; fresh terminal mutations cannot.
Database/provider failures preserve redacted cause chains and request IDs; never
flatten them into wrong-password or unsupported-PRF errors. Each HTTP attempt
has a 15-second client deadline, database lock wait at most 500 ms and transaction
deadline two seconds; a timeout after possible dispatch enters status reconciliation.
The provider ceremony deadline is 120 seconds, independent of a network timeout.

The independent successor-code save/re-entry happened before consume; do not
require a second printing or confirmation ceremony. Before complete the client
reads/verifies that same code from its credential bundle, persists an immutable intent and sends
`next_recovery_key` again with the expected revision and mutation ID. The server
verifies it against the current successor verifier/version outside locks, then rechecks account,
operation, epoch, candidate and receipt before committing. A server can verify
possession of a code, not the physical fact that paper was saved; UI must not
claim otherwise. The old code is never accepted for confirmation.

Complete atomically installs the staged credential and optional grant, confirms
the unchanged successor code version, advances security revision, clears
`active_recovery_id` and marks `Completed`. Key epoch/KDF identity
and existing vault ciphertext never change. Shared-only completion has no grant.
The transaction requires a tested credential and exact body/epoch binding, not
a caller-supplied `verified=true` or `prf_supported=true`.

Return only `{state, revision, completed_at, credential_id}`. The client then
uses ordinary passkey login, obtaining tokens through existing session intent
machinery. This deliberately adds one fresh assertion after recovery completion.
It avoids storing plaintext token replies, encrypted reply caches, or special
recoverable refresh rotation. A lost login response follows ordinary login's
fail-closed rules and can be resolved by a new explicit passkey login.

Delete recovery secrets/intent only after completion read-back, successor-code
save confirmation and durable ordinary-login credential commit. Keep unrelated
profile generations intact. If the client crashes before cleanup, status-only
resume identifies completion without reopening the account or creating sessions.
After cleanup, the new passkey and independently saved successor code suffice.
If the OS bundle is lost, that operation cannot resume. Use the independently
saved current successor in a new consume, or tier-3 recovery if it too is lost.
Previously logged-in devices cannot act as tier 2 after their sessions were
revoked by consumption; offline possession of an E2EE key is not server authority.

## Expiry, reset and bounded resources

- Absolute operation lifetime is 24 hours; reads cannot extend it. Completed and
  terminal status receipts survive seven days, then are deleted. Expiry is checked
  on every request even if background cleanup has not run. Expired operations
  discard staged credentials/grants but preserve the current successor verifier;
  old authority remains revoked. A later consume uses a fresh operation ID/code.
- One active operation/account, four pending/client, one staged credential,
  two challenges/operation, 16 active passkeys/account. Consume/complete bodies
  are at most 8 KiB, WebAuthn finishes 64 KiB, grants 4 KiB, manifests 128 KiB.
  A recovery row is at most 192 KiB with at most 32 mutation receipts; unused
  expired challenges can be replaced at most 16 times. Exhaustion returns a typed
  capacity error and requires explicit abandonment/reset after authority was burned.
- Durable deployment caps are 1,024 active and 8,192 retained recovery operations.
  A short transactional quota row is touched only on operation allocation/release,
  never normal login, status or ciphertext pages. Capacity is checked before burn.
  This low-frequency shared counter avoids a new Redis/control plane; cleanup
  processes indexed pages of at most 100 rows, with one bounded page per tick.
- Per process: 5 consume attempts/minute/normalized locator, 20/source IP/minute,
  60 total/minute; authenticated resume mutations 30/operation/minute. Reuse the
  trusted-proxy IP owner. Limiter storage has 8,192 entries and 15-minute idle
  eviction; on capacity, reject new keys rather than evict a live limit. Bounded
  in-process limits multiply with replicas; durable quota/one-account CAS are
  deployment-wide. The existing KDF semaphore is mandatory and has no unbounded
  waiting queue. No anonymous failed-attempt rows or immutable audit payload dumps.
- These values are one explicit canonical policy in auth configuration/schema,
  read by all producers; no shell defaults. Tests cover configured boundary values.
  Raising limits is an explicit config change, not an alternate recovery mechanism.

Local `zann-server provision reset-recovery-key --email ...` uses the same service,
account lock, epoch bump and supersede transition. It generates a new code, writes
only its verifier and leaves old factors/grants/sessions revoked. Terminal output
is the explicit operator-authorized credential delivery; automation uses the
existing private-file writer. Output failure does not roll back database state:
repeat reset to issue a new code and invalidate the inaccessible prior one.
No E2EE keys/KDF identity/ciphertext change, no raw code in argv/logs/errors.
A disabled user stays disabled. Server-code reset is unavailable in OIDC-only mode.

## Required fault and authorization evidence

- Two clients consume one code: one commit; loser cannot resume winner. Same
  operation retry with correct proof is idempotent, wrong proof/body never is.
- Crash before credential write/read-back/intent/consume commit: no accidental
  burn; crash after commit/response loss resumes without another code or token.
- Failed KDF, stale verifier/version, policy/account disable, epoch change,
  quota saturation and transaction failure leave authority consistent.
- Registration response lost, challenge expiry, candidate assertion lost and
  duplicate finish: one staged factor, no login before complete, bounded receipts.
- Consume activates exactly one saved successor; lost-bundle/expired recovery can
  be superseded by consuming it under a new operation, never by the burned code.
- Complete response lost: candidate activates once, code version stays fixed; resume is
  status-only. Crash before/after ordinary login and cleanup preserves all secrets
  needed to continue and never repeats an ambiguous refresh.
- Admin reset vs consume/complete, expiry vs complete, two finish writers: exact
  lock/revision winner, no resurrection, one audit mutation and intact vault keys.
- A resume token cannot access ordinary/shared/admin/service APIs, another
  operation/account, or ciphertext after completion/expiry. Direct OIDC and
  service-account routes preserve their explicit independent trust policies.
- Restart/pause needs OS secret access, not the personal password/device root;
  local E2EE decryption and full-grant creation still require actual key custody.
- Code-only recovery can complete as Auth-only, but cannot forge a personal grant.
  The Server Recovery Key may ultimately confer eligible shared-server rights;
  no claim of personal decryption, cryptographic erasure or universal ciphertext-only access.
