# ADR 0014: Cross-account discovery and explicit save targets

- **Status:** Proposed
- **Proposed:** 2026-11-15
- **Scope:** `zann-client::app::local`, `zann-client-sqlite`, browser wire/daemon, `zann-ui-core`, native and extension adapters
- **Related:** [ADR 0007](0007-browser-integration.md) (Proposed; implemented phase contracts),
  [ADR 0006](0006-passkey-provider.md) (Proposed),
  [ADR 0010](0010-device-unlock-account-keys.md) (Accepted),
  [ADR 0011](0011-account-scoped-replica-bindings.md) (Proposed)

This is an account-scope extension to the existing browser boundary, not a
replacement channel, pairing scheme or matching implementation.

## Context

Measured in `main` at `d61a8a6` on 2026-11-15:

- [Browser query/fill](../../crates/zann-client-sqlite/src/local_vault/browser.rs)
  uses the selected storage/vault and one account key. Its cursor is selection-bound.
- [Browser save](../../crates/zann-client-sqlite/src/local_vault/browser_save.rs)
  requires an exact `BrowserScope` and rejects a changed selection.
- [DevicePreferences](../../crates/zann-ui-core/src/settings.rs) has no default save target.
- ADR 0007's implemented contracts and the [capability map](../architecture/capabilities.md)
  already own matching, origin evidence, explicit gestures and encrypted delivery.
  Passkey eligibility remains proposed in ADR 0006.

The remaining requirement is finding eligible items across enrolled accounts
without changing the main workspace selection, while making every write destination explicit.

## Proposed decision

1. Add bounded cross-account discovery to the canonical local application port and
   SQLite adapter. Query eligible enrolled/unlocked storages using their own keys;
   retain canonical `zann-autofill` matching and `zann-ui-core` presentation. Project
   account/server badges and stable storage/vault/item references. The main workspace
   remains scoped to its selected account; discovery does not mutate that selection.
2. Bind continuation, selection and release to the discovered account/vault/item
   and current authorization generation. Extend the existing daemon/wire capability
   directly; browser-origin evidence, explicit gestures, encrypted replies and
   stale-result rejection remain mandatory. No shell SQL, per-account secret cache
   in JavaScript or sequential request per matching row is introduced.
3. Show the destination account/vault on save review. A remembered save target must
   be explicitly chosen and owned by the shared preference schema; missing, removed
   or unauthorized targets require selection rather than silent substitution.
   A server-encrypted Shared vault is never an implicit default. First-account
   ordering must not select a destination or imply consent to sharing.

## Acceptance questions and evidence

- Specify the authorized account set, aggregate page/work budget, deterministic
  continuation and cancellation on lock/removal. Reuse current page/account limits;
  do not multiply an unbounded query by the number of accounts.
- Specify account-qualified wire references and their authenticated release lease;
  test duplicate item/vault UUIDs in different storages and a switch/removal between
  discovery and fill/save. Update Rust, WASM and JS consumers in the same cutover.
- Define destination eligibility and stale-preference handling through one policy.
  Test Shared-only accounts with no selected target and an explicit Shared choice.
- Reuse the same account-scope projection for quick search. Passkeys may consume it
  only after ADR 0006 resolves their vault eligibility and verification rules;
  this ADR does not authorize passkey release or creation.

## System alignment review

- **Reuse:** the browser local port, daemon authorization/transport, origin matcher,
  shared presentation and preferences; no new autofill service or ranking owner.
- **Justified divergence:** a selection-only `BrowserScope` cannot describe several
  accounts at once. An account-qualified discovery/release contract is required.
- **Realign on implementation:** pagination, delivery leases and all wire consumers
  move together; native workspace selection remains unchanged.
- **Deferred:** account-set/budget and release contract above block acceptance.
  ADR 0006's unresolved passkey rules remain owned there, not duplicated here.

## Values interrogation

The relevant tests come from [AGENTS.md](../../AGENTS.md), the capability map and
ADR 0007's implemented trust boundary.

| Lever | Trust and custody | SSoT and consolidation | Crash safety and bounds | Cost and verification |
|---|---|---|---|---|
| Aggregate discovery | Each result uses its bound account key; public badges carry no secrets | Reuse local port, matcher and presentation | Fixed aggregate budget and cancellable continuation are required | Wider discovery costs more work; duplicate-ID/paging tests must bound it |
| Account-qualified release | Exact account/item and current origin/gesture remain authoritative | Extend the existing lease/wire contract | Removal/lock invalidates old capabilities | One coordinated consumer cutover; test stale and cross-account substitution |
| Explicit save target | Shared storage requires an explicit destination decision | One shared preference and eligibility policy | Stale target refuses before mutation | One choice when no target exists; test that no hidden default is selected |

## Consequences, debt and alternatives

Discovery becomes independent of the currently visible native vault. It exposes
more public account metadata to the paired extension and increases bounded read
work; the acceptance design must name that metadata and its aggregate limits.
It adds no network server access to the extension or automatic fill/capture.

**Deferred until acceptance:** account availability rules, aggregate budget and
authenticated release references. The implementation should extend existing seams,
not introduce an all-accounts endpoint before these conditions are specified.

Rejected: scanning each account in a shell, using bare item IDs across accounts,
silently using the current/first vault for save, or treating ADR 0006 as accepted.
