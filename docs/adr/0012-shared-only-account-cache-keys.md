# ADR 0012: Local cache keys for shared-only accounts

- **Status:** Proposed
- **Proposed:** 2026-11-15
- **Scope:** `zann-client::app`, `zann-client-sqlite`, `zann-flows`, native enrollment and FFI
- **Related:** [ADR 0009](0009-crypto-format-lifecycle.md) (Accepted),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0011](0011-account-scoped-replica-bindings.md) (Proposed)

This proposal changes shared-only enrollment. It does not authorize new keyring
bytes, implicit password reuse or a second device-unlock hierarchy.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [Enrollment](../../crates/zann-client-sqlite/src/local_vault/account_keys.rs)
  derives an account key from an account encryption password and authenticated KDF identity.
- [DeviceUnlock](../../crates/zann-client/src/app/unlock/model.rs) has bound account
  envelopes without an `AccountPassword`/`LocalCacheKey` origin discriminator.
- The shared [unlock flow](../../crates/zann-flows/src/unlock.rs) routes unenrolled
  accounts to account-password phases. It has no dedicated passwordless shared-only branch.
- [Canonical key proof](../../crates/zann-client/src/app/account_keys.rs) enforces
  an existing key fingerprint, including shared-cache bindings.

A shared-only OIDC account needs an encrypted offline cache, but no personal-vault
E2EE password. Treating a newly generated cache key as interchangeable with an
already bound key would strand existing cached data.

## Proposed decision

1. When authenticated server policy disables personal vaults, use a random local
   cache key instead of inventing an account encryption password. The first account
   still requires an explicitly chosen device-unlock password; subsequent shared-only
   accounts reuse the unlocked device root, not that password as account key material.
2. Extend the existing account envelope's policy with an explicit key origin so
   shared-only cache custody cannot be mistaken for a personal E2EE key. Bind it to
   the same device/storage/server/subject and verified CAS owner as ADR 0010.
   Reuse the existing verified crypto primitives; do not introduce a new keyring file.
3. Keep personal-key proof and shared-cache key admission in the canonical app/sync
   owner. For an existing replica, first resolve and verify its bound key. A fresh
   random key must never replace a readable cache merely because the server is shared-only.

## Acceptance questions and evidence

- Define the authenticated policy source and enrollment result for accounts without
  account KDF material. No shell may infer shared-only status from an empty vault list.
- Resolve how existing shared-cache fingerprints and cached/pending data transition.
  Preserve the old readable binding until a verified, crash-safe transition commits;
  define refusal/recovery for an incompatible source before accepting this proposal.
- Specify origin encoding under ADR 0009, intentional fixture updates and explicit
  cutover notes. No automatic legacy reader or new v2 crypto envelope is authorized here.
- Test fresh shared-only setup, a second shared-only account without another account
  password prompt, restart/remembered unlock, incompatible fingerprints, and a
  shared-only-to-personal policy change that requires explicit personal-key enrollment.

## System alignment review

- **Reuse:** the random device root, account envelopes, Config generation lease,
  exact-source SQLite CAS and shared flow/FFI adapters.
- **Justified divergence:** a local random cache key has a different purpose from
  a password-derived personal key; an explicit origin makes that difference auditable.
- **Realign on implementation:** account enrollment/proof, shared-cache admission
  and unlock routing consume one typed result; shells only render the required prompts.
- **Aligned as-is:** personal vault keys remain client-side and server shared-vault
  encryption remains server-owned. No device/cache key is sent to the server.

## Values interrogation

The governing tests are the repository invariants in [AGENTS.md](../../AGENTS.md)
and [ADR 0010](0010-device-unlock-account-keys.md), not an additional values schema.

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Shared-only prompt policy | Authenticated policy, not missing data, selects the key purpose | One app result drives the existing shared unlock flow | Re-check policy/binding at commit | One device setup remains; test zero extra account-password prompts |
| Explicit key origin | Prevents a cache key becoming personal E2EE authority | Extend the existing account envelope; no parallel bag | Strict decode, existing limits and verified CAS remain required | One schema change; frozen fixtures and purpose-confusion tests |
| Existing-cache admission | Never discard a bound key or unsent plaintext access | Reuse canonical proof/fingerprint owner | An unresolved transition must refuse before publication | Existing-replica handling is deferred below; crash/restart tests gate acceptance |

## Consequences, debt and alternatives

Shared-only enrollment removes an unnecessary secret and another account KDF.
Cold unlock retains one device-password derivation and opens enrolled key envelopes;
no per-account network operation is added to offline unlock. It adds origin/policy
handling and an explicit existing-cache transition design.

**Deferred until acceptance:** existing-cache transition and later personal-vault
enablement must specify lossless behavior in this ADR. They cannot be waived as UX
details or compensated by a silent fallback. No runtime behavior changes in this PR.

Rejected: reusing a login/device password implicitly, generating a new cache key
on every login, or treating a Shared vault as client E2EE.
