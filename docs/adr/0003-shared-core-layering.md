# ADR 0003: One door, headless core, inverted platform dependencies

- **Status:** Proposed
- **Date:** 2026-08-09
- **Supersedes:** the *Plan* and *Alternatives* sections of ADR 0001. Its
  diagnosis stands; its ordering and one of its rejections do not.

## Context

ADR 0001 identified the fork, the re-implemented connect flow, the split detail
model and the labels-as-code problem. All four are still true, and the fork has
grown since it was written:

| | ADR 0001 (2026-08-05) | measured 2026-08-09 |
|---|---|---|
| `apps/desktop/src-tauri/src` | 9 378 | 9 841 |
| `apps/cosmic/src` | 2 100 | 2 548 |
| `auth_oidc.rs` desktop / client | 541 / 476, 257 differing | 541 / 587, 214 differing |

Four things were not visible then.

**The fork has produced a behavioural regression, not just duplication.**
`crates/zann-client/src/sync_helpers.rs:306,431` decides a pull-side tombstone
from `change.deleted_at`. The server never sends that field — `SyncPullChange`
(`domains/sync/http/v1/types.rs:45-58`) signals deletion through `operation`, and
the client declared the field itself with `#[serde(default)]`, so it is
permanently `None`. The desktop does it correctly at `:332` and `:444`; the
client's only `ChangeType::Delete` branch sits at `:221`, in the push path.
COSMIC runs on the client side, so **remote deletions never arrive in COSMIC**.
Five smaller divergences sit alongside it: `>=` for `>`, `cache_key_fp: None` for
`Some(key_fp)`, and `replace_by_item` for the sync-aware `merge_by_item`.

**The dependency direction is the actual obstacle to new platforms.** The core
reaches down to the OS — `keyring`, `ctap-hid-fido2`, `rfd`, `dirs::home_dir` in
ten places, `TcpListener::bind("127.0.0.1:8765")` for the OIDC redirect. Each is
individually small and collectively fatal: none of them exists on iOS or Android,
and no amount of code sharing helps while the arrows point that way.

**The facade is far from complete.** 68 Tauri commands against 26 `uniffi`
exports, two of which are `Unimplemented` stubs. COSMIC bypasses it into
`zann-client` for authentication precisely because the facade has none.

**`$HOME` is assumed everywhere, and it is already broken.** `CoreFacade.root`
derives from `db_url` (`zann-ffi/src/lib.rs:200,744`) while `remote_sync` reads
`client_root_path()` = `$HOME/.zann` (`:703,767`). With `ZANN_DB_URL` outside
`~/.zann` — which `apps/cosmic/src/backend/mod.rs:34` supports — login writes
tokens to one directory and sync reads from another.

## Decision

**1. `zann-ffi` is the only door.** No file under `apps/` imports `zann_client`,
`zann_db`, `zann_crypto` or `zann_keystore`; Rust clients may additionally use
`zann_ui_core`. Enforced by a script in CI alongside the existing
`scripts/check-audit-surface-deps.sh`, seeded with an allowlist of today's
violations that each phase shrinks. An empty allowlist means the migration is
done.

**2. Application logic lives in a headless `zann-app`.** Session, autolock,
clipboard policy, items, vaults, storage, history, backup and sync
orchestration — no toolkit, no `$HOME`, no blocking runtime. `zann-ffi` becomes a
mechanical projection: one delegating call plus a type mapping per method, held
there by a CI ceiling on its non-test line count.

**3. Platform dependencies invert.** A new `zann-platform` holds *only* traits —
`AppPaths`, `SecretStore`, `PresenceGate`, `HardwareKeyPort`, `RedirectTransport`,
`FileGateway`, `Clipboard` — with zero OS dependencies. `zann-platform-desktop`
implements them for desktop; Swift and Kotlin implement them as `uniffi` foreign
traits. The host hands capabilities inward instead of the core reaching outward.
This is what makes `RedirectTransport` testable without opening a socket, and it
is the same shape a mobile OIDC flow needs.

**4. Errors cross the boundary as an open `{ kind, message }` contract**, exactly
as `zann_core::ServiceError` (`crates/zann-core/src/services.rs:88`) already
models and as `zann_keystore::remembered.rs:81-84` already documents. A closed
enum was rejected: every new `kind` would become a source-breaking change in all
clients simultaneously, including ones awaiting App Store review.

**5. Mobile clients are native, built on generated `uniffi` bindings.** Tauri v2
could target mobile and `gen/` shows it has never been tried. It is not the
saving it appears to be: the paths, the blocking runtime, the loopback redirect,
the `reqwest → native-tls → openssl-sys` chain and the absent mobile keystore
backends are the same work either way, and only the UI layer is spared.
Meanwhile iOS AutoFill is a separate native target under a ~120 MB budget, and
`kdf_fingerprint` (`crates/zann-crypto/src/passwords.rs:23-32`) hashes
`memory_kb`, so Argon2id parameters are part of the vault's identity and cannot
be lowered on-device — the extension must unwrap a stored key rather than derive
one, which is native work regardless. The decision is reversible: an FFI-first
core keeps a Tauri mobile shell available as a cheap fallback.

**6. Binding generation turns on early, mobile clients arrive late.** Crossing the
FFI boundary as an FFI boundary has never been tested — COSMIC links the rlib and
calls `debug_create_kv_item`, a `#[cfg(debug_assertions)]` symbol outside the
export block, which is why `flake.nix` carries `doCheck = false`. Generate Swift
and Kotlin plus cross-compilation checks before the facade grows, so each added
method is proved expressible when it is added rather than in bulk afterwards.

**7. Safety comes before movement, and export comes before both.** Per ADR 0002,
export lands first. Then the CI net and a red-first test oracle; only then the
sync reconciliation, which rewrites the local SQLite write path.

### Relationship to ADR 0001

ADR 0001 rejected "put everything behind `zann-ffi` including the flows", on the
grounds that a `uniffi` boundary makes state machines awkward to observe. That
reasoning was right and the conclusion is refined rather than reversed: the flows
live in `zann-app` as ordinary Rust, which Rust clients use directly, and are
projected across the boundary for non-Rust clients through an exported
`ZannObserver` callback trait. The awkwardness ADR 0001 anticipated is real, and
the observer is the price of admitting Swift and Kotlin at all.

## Consequences

**Good.** A fix lands once. Drift becomes a build failure rather than a habit —
the layering check and the binding-drift job catch the two classes that produced
the current mess. The port inversion makes auth and file handling testable
without a socket or a file dialog, which is a present-day benefit and not only a
mobile one. Facade completeness is what COSMIC, the native-messaging host and any
mobile client all need, so one effort serves all three.

**Bad.** The sync reconciliation is the highest-risk change in the programme: two
implementations differ on six points at once and both write to the same
`~/.zann/local.sqlite`. Bringing `src-tauri` into the workspace triples the
dependency graph (932 packages) and adds +3 584/−197 lines to the root lockfile;
`apps/cosmic` cannot join at all, because its lockfile carries 51 git sources
that Nix vendoring depends on. Users who have lived with "deletions never
arrive" will see items disappear once it is fixed, which reads as data loss.

**Unresolved.** Concurrent access to `~/.zann` by two clients on one machine. The
schema and semantics get aligned, the race does not. ADR 0002 answers it with a
daemon; until that exists, WAL and `busy_timeout` are the only mitigation and the
limitation should be documented rather than left implicit.

## Plan

Phases, in order. Each is independently shippable; risk is *low* (revertible, no
product impact), *medium* (behaviour changes, covered by a test) or *high*
(touches user data or authentication).

| | Phase | Risk |
|---|---|---|
| 0 | Export from COSMIC; snapshots and `verify` (ADR 0002) | low |
| 1 | CI safety net: local e2e, COSMIC job, layering guard, `src-tauri` into the workspace, `default-features = false` on `reqwest` | low |
| 2 | Red-first oracle: pull-path tests, KDF known-answer tests across all four `derive_master_key` copies | low |
| 3 | Free deletions: byte-identical files, duplicate crypto modules, 283 unused DTOs | low |
| 4 | Field masking through the existing `SecurityProfileRegistry` | medium |
| 5 | Sync reconciliation — desktop semantics win | **high** |
| 6 | `zann-platform` ports, one `config.json`, `tracing` | medium |
| 7 | Bindings and mobile compile checks | low–medium |
| 8 | Auth reconciliation and `RedirectTransport` | **high** |
| 9 | `zann-app`: services out of the Tauri binary; implement autolock | medium |
| 10 | Facade completeness, structured errors, async, observer | medium |
| 11 | COSMIC on the facade only — gains create, edit, delete | medium |
| 12 | Tauri on the facade only; generate TypeScript types | **high** |
| 13 | Native-messaging host and daemon; then mobile ports and clients | medium |

Expected effect on the cost of a client: a Rust client falls from 6 000–9 000
lines to 1 200–1 800, and `apps/desktop/src-tauri` from 9 841 to roughly 1 500.
Non-Rust clients go from impossible to about 600 lines of port implementations
plus their own views.

## Alternatives considered

**Reconcile the fork without the layering guard.** Cheaper, and exactly how the
current state arose — ADR 0001 proposed the same reconciliation four days before
the fork grew by 463 lines. Rejected: without a build-time check the work is
undone by the next feature.

**A closed error enum across the boundary.** Better ergonomics in Swift and
Kotlin. Rejected for the release-coupling reason above.

**Keep `zann-keystore`'s platform backends where they are and add mobile ones
beside them.** Fewer crates. Rejected: it keeps `cfg` branching on a public type,
which is how `UnlockError` would fork per target the moment it starts carrying a
`kind` across the boundary.

**Move `apps/cosmic` into the workspace for uniform CI.** Rejected on evidence:
51 git sources in its lockfile against zero in the root, and `flake.nix` pins
`cargoRoot = "apps/cosmic"`. A separate CI job gives the same guarantee.
