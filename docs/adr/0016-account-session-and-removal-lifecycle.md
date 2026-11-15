# ADR 0016: Account sign-out, trust forgetting and local removal

- **Status:** Proposed
- **Proposed:** 2026-11-15
- **Scope:** canonical auth/config/local recovery owners, shared flows, native account UI and FFI
- **Related:** [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0011](0011-account-scoped-replica-bindings.md) (Accepted),
  [ADR 0008](0008-device-unlock.md) (Proposed lifetime/UV policy)

This proposal aligns user actions with existing owners. It does not propose a
second deletion engine, change remembered-unlock lifetime, or promise secure erasure.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [AppSession logout](../../crates/zann-client/src/session.rs) distinguishes remote
  logout outcome from local credential revocation through the canonical journal.
- [Connection removal](../../crates/zann-client/src/app/connection_removal.rs)
  forgets sign-ins/trust locally; its repository operation removes the connection
  and its profiles. It does not delete the encrypted local replica.
- [Scoped local recovery](../../crates/zann-client-sqlite/src/local_vault/recovery.rs)
  already previews unsent/dirty/history data, saves an encrypted snapshot, reserves
  the SQLite writer and deletes the selected replica/key slot. Device reset retains
  Config sign-ins/preferences and disarms remembered unlock.
- [The capability map](../architecture/capabilities.md) documents that recovery can
  leave a disconnected encrypted replica if an external Config commit fails.

The remaining requirement is a consistent account lifecycle in native UI/shared
flows, particularly once several subjects share one endpoint under ADR 0011.

## Proposed decision

1. **Sign out of this account:** use canonical session logout and local credential
   retirement. Retain its endpoint trust, encrypted replica and enrolled key so
   offline work remains readable. Show remote revocation as confirmed, unconfirmed
   or not attempted according to the typed outcome; do not claim guaranteed remote
   revocation when offline. Reconnection must prove the same account/storage binding.
2. **Forget this server's trust/sign-ins:** use the existing endpoint connection
   owner. Present all affected profiles when an endpoint is shared by accounts;
   leave their encrypted replicas/keys disconnected. This action must not masquerade
   as signing out one account or removing its local data.
3. **Remove this account from this device:** reuse the existing scoped recovery
   preview/confirmation, snapshot and validated deletion. Under ADR 0011 remove only
   the selected profile's replica/key/credentials, preserving other profiles and
   their shared endpoint pin. Keep whole-device reset a distinct existing scope.

## Acceptance questions and evidence

- Define the shared lifecycle states and actions, including configured accounts
  without a cached replica and disconnected replicas without credentials. Reuse
  current account location/key-binding projections; shells must not infer state
  from errors or invent their own reconnect rules.
- Preserve ADR 0011's implemented profile-scoped credential removal. Whole-endpoint
  removal operation must not be called as a one-profile deletion after that cutover.
- Preserve recovery from locked setup and existing unsent-data confirmation. Test
  stale preview, same-cardinality edits, snapshot failure, interruption and a second
  account continuing to work. Reuse exact-source checks and existing journals;
  define repeat/restart outcomes instead of adding a separate recovery command family.
- State the retention boundary explicitly: recovery snapshots and older backups
  retain removed keys/data. Removing a live key slot is not erasure of every copy;
  mandatory `VACUUM` cannot establish that promise. This proposal does not delete
  recovery copies or change their retention policy.

## System alignment review

- **Reuse:** AppSession auth journal, Config credential retirement, account selection,
  recovery preview/source proof, SQLite transaction and encrypted snapshot owners.
- **Justified divergence:** sign-out, endpoint trust forgetting and account-data
  deletion have different scopes and retained state; they need distinct user actions.
- **Realign on implementation:** profile removal and all native/FFI consumers use
  one shared lifecycle projection; endpoint-wide actions enumerate their real impact.
- **Aligned as-is:** ADR 0010's stable device root and historical snapshots;
  ADR 0008 continues to own proposed SessionOnly/PIN/UV semantics.

## Values interrogation

The tests are the trust/custody, SSoT, crash-safety and bounded-work invariants in
[AGENTS.md](../../AGENTS.md) and the capability map.

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Account sign-out | Revokes local session authority without deleting offline secrets | Reuse AppSession journal and typed remote outcomes | No automatic ambiguous remote replay; explicit reconnect | One scoped action; test offline/unconfirmed outcome and retained data |
| Endpoint forgetting | Makes loss of a shared pin and all its sign-ins explicit | Reuse the existing connection owner | Exact config source controls the affected set | UI must name affected profiles; test that replicas remain disconnected |
| Account removal | Deletes only selected live data; snapshots remain recoverable | Reuse scoped recovery rather than duplicate SQL/flows | Preview proof, snapshot-before-delete and writer transaction remain required | Snapshot I/O scales with the existing device database; test preservation of another account |

## Consequences, debt and alternatives

Users can choose the intended scope without losing unsent data to an ambiguous
label. Local deletion still incurs the existing encrypted snapshot cost; it does
not add an export/re-import ceremony or require server reachability. Independent
accounts must not share a new global sign-out/recovery singleton in the UI.

**Deferred until acceptance:** lifecycle projection and profile-scoped mutation
contracts, coordinated with ADR 0011. Existing recovery behavior remains supported;
its cross-store failure semantics must be retained, not described as one global
atomic transaction.

Rejected: one generic Forget button for all scopes, account removal implemented
again in each shell, calling local connection removal a confirmed remote logout,
or advertising cryptographic erasure while retaining recoverable snapshots.
