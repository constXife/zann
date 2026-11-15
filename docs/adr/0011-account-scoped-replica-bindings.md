# ADR 0011: Account-scoped replica bindings on one server

- **Status:** Proposed
- **Proposed:** 2026-11-15
- **Scope:** `zann-client::config`, `zann-client::app`, `zann-client-sqlite`, native account selection
- **Related:** [ADR 0001](0001-shared-client-core.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0016](0016-account-session-and-removal-lifecycle.md) (Proposed)

This proposal extends account cardinality; it does not replace ADR 0010's keyring
or authorize a persisted-format cutover.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [ConfigV2](../../crates/zann-client/src/config/v2/journal_model.rs) already stores
  `account_identities` by connection/profile. There is no global account identity to migrate again.
- [ConnectionMetadata](../../crates/zann-client/src/config/v2/schema.rs) still owns
  `storage_id` and `expected_master_key_fp`.
- [Authenticated target admission](../../crates/zann-client/src/config/v2/authenticated_target.rs)
  prohibits endpoint aliases and rejects a different storage binding on an existing connection.
- [Account-key resolution](../../crates/zann-client/src/app/kdf_identity.rs) combines
  that connection's storage with the selected profile's canonical account subject.

Inference: independent offline replicas for two subjects on one endpoint need
profile-scoped bindings. Multiple configured profiles alone do not supply that capability.

## Proposed decision

1. Keep normalized endpoint identity, server ID and TOFU fingerprint on the existing
   `ConnectionConfig`. Two subjects on the same endpoint share its trust decision;
   a second account cannot create an alias to bypass or replace the pin.
2. Move replica storage UUID and expected account-key fingerprint from connection
   metadata to the corresponding `CredentialProfile`. Reuse `account_identities`
   for per-profile KDF identity. A remote-only profile has no replica binding;
   a native replica has exactly one explicit binding. Enforce uniqueness of the
   enrolled `(server_id, account_subject)` and of the storage UUID, using authenticated
   subjects rather than email, profile labels or whichever account is visible.
3. Update canonical target resolution, generation leases, credential anchors,
   sync, account selection and removal together. The keyring continues to bind
   device/storage/server/subject as ADR 0010 requires. No active-profile inference
   may substitute for a binding captured by an operation.

## Acceptance questions and evidence

- Specify the exact profile schema and direct Pre-GA cutover, including how an
  existing connection-level binding is assigned without guessing among profiles.
  Ambiguous state must be refused with an explicit preservation/recovery path.
  Do not add a compatibility reader, dual write or automatic fallback binding.
- Prove two subjects on one endpoint can enroll, sync, restart and export independently;
  changing a credential profile or UI selection cannot redirect an in-flight operation.
- Test duplicate subject/storage rejection, unchanged TOFU pinning, and removal or
  logout of one account leaving the other account's credentials, keys and data intact.
- Cover native and FFI consumers plus remote-only CLI profiles before acceptance.

## System alignment review

- **Reuse:** Config/profile repositories, authenticated endpoint uniqueness and
  generation leases remain the owners; `DeviceUnlock` remains the sole keyring policy.
- **Justified divergence:** replica binding changes cardinality from one per
  connection to one per account profile. This is not a second connection or keyring model.
- **Realign on implementation:** all connection-level replica/fingerprint consumers,
  including recovery in ADR 0016. Remove the superseded fields in the same cutover.
- **Aligned as-is:** ADR 0010's random device root and per-account encryption envelopes.

## Values interrogation

There is no separate repository values manifest/template. The tests below apply
the trust, custody, SSoT, crash-safety and bounded-work invariants in
[AGENTS.md](../../AGENTS.md) and the [capability map](../architecture/capabilities.md).

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Shared endpoint trust | Adding a subject cannot weaken the existing pin | Reuse the connection's single trust record | Existing authenticated target checks gate writes | No repeated trust ceremony; test alias/pin replacement rejection |
| Per-profile replica binding | Exact subject/storage/fingerprint prevents cross-account key use | Move existing fields; reuse the KDF identity map | Retain bounded config validation and exact generation leases | Consumer changes are required; test two subjects on one endpoint |
| Coordinated cutover | Never infer an account from a label or active screen | Delete connection-level binding after all consumers switch | Refuse ambiguous source before writing; no dual-write interval | Cutover handling is unresolved below, not hidden as compatibility |

## Consequences, debt and alternatives

This enables personal/admin accounts on one server without separate client roots.
The implementation cost is a coordinated schema/consumer change, not a new crypto
format or an extra per-unlock KDF. Independent accounts can use independent profile
records; adding one does not require rewriting a central account registry in code.

**Deferred until acceptance:** exact cutover mapping and its preservation procedure
belong to this ADR's implementation design; acceptance requires the ambiguity and
restart tests above. This documentation creates no MIG exception.

Rejected: duplicate connections for the same normalized endpoint, email-based
account identity, or a parallel native-only profile store. Each would split trust
or account ownership instead of fixing its cardinality.
