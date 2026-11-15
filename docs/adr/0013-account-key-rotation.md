# ADR 0013: Account-key rotation with scoped recovery

- **Status:** Proposed
- **Proposed:** 2026-11-15
- **Scope:** canonical client/server account-encryption protocol, `zann-client::app`, `zann-client-sqlite`, shared flows
- **Related:** [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0011](0011-account-scoped-replica-bindings.md) (Proposed),
  [ADR 0012](0012-shared-only-account-cache-keys.md) (Proposed)

This records rotation requirements and acceptance blockers. It is not a new
rotation protocol, and it does not turn device password change into account rotation.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [Device password change](../../crates/zann-client-sqlite/src/local_vault/unlock.rs)
  rewraps the stable root locally; it preserves account envelopes and server data.
- [Account insertion](../../crates/zann-client/src/app/unlock/accounts.rs) refuses
  an already enrolled storage; it is not an account-key replacement API.
- [Sync/enrollment proof](../../crates/zann-client/src/app/account_keys.rs) rejects
  an unexpected bound fingerprint. There is no `KeyRotationRequired` flow state.
- ADR 0010 expressly leaves account-key rotation and transfer/recovery protocols out of scope.

An account key changed on another device must not lock unrelated accounts or make
the affected account's existing offline cache and pending changes unreadable.
Replacing one keyring entry alone does not establish that preservation property.

## Proposed decision

1. Own account-encryption rotation in the canonical application/protocol boundary.
   Verify the current source and trial-decrypt every candidate rewrap before any
   commit, reusing ADR 0009. Define a retryable, idempotent remote/local transition;
   an ambiguous remote outcome must not cause an unproven key to be published locally.
2. Represent an authenticated account-key mismatch as a scoped action-required state
   for its storage. Keep unrelated accounts operational and retain access to the
   old account's cache, dirty items and local history until reconciliation proves
   how they move. Never classify every crypto error as evidence of remote rotation.
3. Keep device password change independent. A UI may offer an explicit, separate
   device-password action after account rotation, using the existing API and current
   device-password check. Do not silently reuse the new account password or select
   that action from an account-count heuristic.

## Acceptance questions and evidence

- Specify the authenticated signal distinguishing rotation from corruption, wrong
  credentials or a changed server pin. Define the account KDF/fingerprint generation
  and publication ordering for a second device and concurrent writers.
- Specify cache-key handling: account-encrypted cached material must remain readable
  until verified re-encryption or another explicitly designed custody transition.
  Include server-wrapped shared cache, pending writes and locally retained history.
- Define crash/restart behavior before/after each remote and local commit, request
  deadlines, cancellation and bounded batch sizes. Reuse existing journals/CAS where
  their semantics fit; no collection of manual `recover-*` commands is the default.
- Test concurrent rotation, publication losers, network ambiguity, stale config,
  wrong replacement secrets, offline restart and unaffected-account operations.

## System alignment review

- **Reuse:** account proof/binding, verified crypto writers, generation leases,
  operation cancellation and local device-password rewrap.
- **Justified divergence:** account rotation crosses remote and local generations;
  a local device-password CAS cannot express it.
- **Realign on implementation:** account identity, remote vault envelopes, keyring,
  cache ownership and pending sync reconcile through one protocol and shared flow.
- **Deferred:** authenticated rotation evidence and recoverable commit ordering are
  unresolved here and block acceptance, not the creation of this Proposed document.

## Values interrogation

Apply the trust/custody, SSoT, crash-safety and bounded-work tests in
[AGENTS.md](../../AGENTS.md) and ADR 0009 to each lever independently.

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Canonical rotation transition | Server never receives personal keys/plaintext; candidates prove decryption | Extend account/sync owners, not shell crypto | Idempotent publication and bounded rewrap batches are required | A complete protocol is deferred below; fault traces gate acceptance |
| Scoped mismatch handling | Only authenticated evidence changes account state | One shared action-required projection | Keep old readable data; reject stale generations | Test one affected account alongside a working second account |
| Independent device action | No implicit password reuse or custody coupling | Reuse current local rewrap API | Account completion cannot depend on a second device CAS | An optional explicit action replaces the proposed checkbox heuristic |

## Consequences, debt and alternatives

This preserves offline work and separates server login, account encryption and
device unlock. Rotation may require paged local re-encryption and multiple bounded
remote requests; their cost and exact recovery trace must be measured in the
implementation design before acceptance. Unrelated-account work must not require
a device-wide rotation ceremony or a second implementation per shell.

**Deferred until acceptance:** the protocol evidence/order and cache transition
listed above. They remain design debt in this ADR; no implementation or fallback
is licensed by naming an action-required state.

Rejected: overwriting the account key first, dropping pending data to reconnect,
device-wide lock on one mismatch, or automatically changing the device password.
