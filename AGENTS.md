# Repository Guidelines (AGENTS.md)

This file is the operational map for humans and AI agents working in `zann`.
Normative details live in `docs/`; when a summary here diverges from a canonical
document below, the canonical document wins.

## Source of Truth (Read in This Order)

1. [`docs/Architecture.md`](docs/Architecture.md) & [`docs/architecture/capabilities.md`](docs/architecture/capabilities.md) — client architecture, single-owner capability map, allowed dependencies, and the active `MIG-*` exception ledger.
2. [`config/architecture-boundaries.json`](config/architecture-boundaries.json) — machine-enforced package graph, feature contracts, and source rules checked by `./scripts/check-client-architecture.sh`.
3. [`docs/adr/`](docs/adr/) — architectural decisions:
   - [ADR 0001](docs/adr/0001-shared-client-core.md): shared client core & thin interface shells;
   - [ADR 0002](docs/adr/0002-client-strategy.md): client strategy (`Rust Core + Thin Native Shells` across Linux COSMIC, Apple SwiftUI for macOS/iOS/iPadOS, Android Jetpack Compose, Tauri desktop, and Browser Extension + Daemon);
   - [ADR 0004](docs/adr/0004-machine-secret-plane.md) & [ADR 0005](docs/adr/0005-runtime-secret-delivery-profiles.md): machine secret plane & runtime delivery profiles.
4. [`crates/zann-server/SECURITY.md`](crates/zann-server/SECURITY.md) & [`docs/audit-surface.md`](docs/audit-surface.md) — server threat model and client/server security audit surface.
5. [`docs/ux/`](docs/ux/) — unified UX contracts, layout breakpoints, and theme tokens.
6. [`CONTRIBUTING.md`](CONTRIBUTING.md) — workflow, CI gates, and PR conventions.

---

## Stage & Proportionality

Zann is currently **Pre-GA (experimental prior to `v0.Y`)**.

- **Strict at every stage (never compromise):**
  - **Trust-model separation:** Personal vaults (`VaultEncryptionType::Client`) are end-to-end encrypted on the client; the server is opaque storage. Shared vaults (`VaultEncryptionType::Server`) use server-side encryption (`ZANN_SMK`). Never leak personal vault keys or plaintext outside the local client boundary.
  - **Secret custody:** Never log, print, pass via CLI argv, or derive `Debug` on plaintext secrets, master keys, passwords, or bearer/refresh tokens. Persist files containing tokens, configs, or plain exports with owner-only permissions (`0600` / `0700`).
  - **Single canonical owner (SSoT):** Every domain, sync, auth, crypto, config, and presentation capability has exactly one owner in [`docs/architecture/capabilities.md`](docs/architecture/capabilities.md).
  - **Crash-safe & idempotent transitions:** Config locks, credential journals, and SQLite sync transactions (`(cursor, last_seq)` checkpoints) must remain atomic and fail-closed.
  - **Bounded hot paths:** Server endpoints, sync catalog reconciliation, and local SQLite queries must remain bounded in cardinality and sequential round trips.

- **Pre-GA proportionality (avoid premature ceremony):**
  - **No fallback or dual-write by default:** When all consumers of an internal API or crate live in this repository, perform a direct cutover in-place and delete the superseded code in the same change.
  - **Compatibility paths require explicit bounds:** Any temporary migration shim must be recorded in [`docs/architecture/capabilities.md`](docs/architecture/capabilities.md) and [`config/architecture-boundaries.json`](config/architecture-boundaries.json) with an owner, compensating test, and measurable removal condition.
  - **Subtractive balance:** Touching a legacy path under an active `MIG-*` exception must narrow or remove the exception rather than expanding it.

---

## Three-Layer Client Architecture

Dependencies point strictly downward (`[SHELL]` → `[PRESENTATION]` → `[CORE]`). Lower layers never import UI toolkits, CLI parsers, or FFI wrappers.

### 1. `[CORE]` — Domain, Crypto, Storage, Transport & Application Services
- `crates/zann-core`: domain models, vault/item invariants, pure policies, wire DTOs (`zann-core::api`).
- `crates/zann-crypto`: sole owner of Argon2id KDF, ChaCha20-Poly1305 envelopes, payload checksums, and secret key types.
- `crates/zann-db` & `crates/zann-client-sqlite`: database repositories, migrations, and the production SQLite sync store adapter. The opt-in `zann-client-sqlite/local-vault` feature implements local vault operations and maintenance behind `zann-client::app::local`.
- `crates/zann-keystore`: OS secret-store (`keyring`) and FIDO2 hardware-key (`hmac-secret`) unlocking.
- `crates/zann-client`: canonical client crate (`remote`, `config`, `session`, `sync`, `delivery`, the canonical `zann-client::app::AppClient` facade, the local-vault port, and bounded server-oriented remote capabilities).
- **Portability rule:** Shared core crates must remain cross-compilable to `aarch64-apple-ios`, `aarch64-apple-darwin`, `aarch64-linux-android`, and Linux without implicit `$HOME` lookups or desktop-only C dependencies in default feature sets.

### 2. `[PRESENTATION]` — Toolkit-Neutral View Models & Flows
- `crates/zann-ui-core`: categories, item counts, client-side filtering, folder trees, field ordering/masking, TOTP generation, server URL normalization, and device preference schemas.
- `zann-flows` (planned): headless state machines (`handle(State, Event) -> (State, Vec<Effect>)`) with operation IDs and cancellation.

### 3. `[SHELL]` — Native Interfaces & Edge Adapters
- `apps/cosmic`: COSMIC-native (`libcosmic` / Iced) reference desktop client for Linux. Links `[CORE]` and `[PRESENTATION]` directly in Rust.
- `apps/desktop`: Tauri desktop app (`src/` Vue 3 + TypeScript frontend, `src-tauri/` Rust backend).
- `crates/zann-cli`: server-oriented CLI (`zann-client` `remote` + Config v2 + `CredentialStore` + `delivery` surfaces, free of SQLite and GUI deps).
- `crates/zann-ffi`: UniFFI edge adapter projecting `[CORE]` and `[PRESENTATION]` to non-Rust clients (`apps/apple` SwiftUI for macOS/iOS/iPadOS and `apps/android` Jetpack Compose). Rust clients must not use `zann-ffi` for new capabilities (`MIG-003`).
- **Shell rule:** Shells own only widgets, layout, navigation, CLI I/O, and OS capability adapters (clipboard, tray, biometrics, file dialogs, browser launch, autofill extensions). Never implement crypto, HTTP routes, sync merge rules, or category/masking logic in a shell.

---

## Structural Budgets & Consolidation

To keep modules navigable and prevent merge collisions across concurrent changes:
- **File size budget:** `> 400` non-test lines is a review signal; `> 1,000` non-test lines is a hard ceiling — do not add new responsibilities to a file over 1,000 lines without extracting a focused submodule first.
- **No God-modules:** Keep screen state machines (`apps/cosmic/src/screens/*.rs`), server domains (`crates/zann-server/src/domains/*`), and FFI projections split by domain rather than accumulating everything in `main.rs` or `lib.rs`.
- Before introducing a new crate, module, endpoint, or cross-client flow, apply [`.agents/skills/consolidation-check/SKILL.md`](.agents/skills/consolidation-check/SKILL.md).

---

## Review & Verification Tiers

Match verification depth to the blast radius of the diff:

- **T0 — Documentation, translations (`i18n/`), or comments only:**
  - Verify links and accuracy against the code; no heavy test suites required.
- **T1 — Contained implementation within one crate or shell screen (no boundary/contract change):**
  - Run `cargo fmt --check`, `cargo clippy` and `cargo test` for the affected package (`cargo test -p <crate>`, `just cosmic-test`, or `just desktop-test`).
  - Check consolidation rules ([`.agents/skills/consolidation-check/SKILL.md`](.agents/skills/consolidation-check/SKILL.md)).
- **T2 — Boundary, architecture, or security audit-surface change:**
  - Triggered by changes to paths in [`docs/audit-surface.md`](docs/audit-surface.md), `crates/zann-crypto/**`, `crates/zann-keystore/**`, `crates/zann-client/**`, `crates/zann-client-sqlite/**`, `crates/zann-server/src/domains/{auth,access_control}/**`, `crates/zann-ffi/**`, `config/architecture-boundaries.json`, or `AGENTS.md`.
  - Run `./scripts/check-client-architecture.sh` and `./scripts/check-audit-surface-deps.sh` (via `direnv exec .` on NixOS).
  - Run [`.agents/skills/security-change-review/SKILL.md`](.agents/skills/security-change-review/SKILL.md) and [`.agents/skills/consolidation-check/SKILL.md`](.agents/skills/consolidation-check/SKILL.md).

---

## Build, Test, and Development Commands

> On NixOS, prefix commands with `direnv exec .` (or use `nix develop .#cosmic` for `apps/cosmic`).

- `cargo build` — build the root Rust workspace.
- `cargo test` (or `just fast-test`) — run the fast, no-DB workspace test suite.
- `cargo fmt` / `cargo clippy --all-targets --all-features -- -D warnings` — format and lint Rust code (warnings are errors in CI).
- `just architecture-check` (`./scripts/check-client-architecture.sh`) — validate client-layer ownership, dependency direction, and `MIG-*` exceptions.
- `./scripts/check-audit-surface-deps.sh` — validate `zann-crypto` dependency isolation.
- `just cosmic-test` (`cd apps/cosmic && cargo test`) — run headless flow and backend tests for the COSMIC client.
- `just cosmic-run` / `nix build .#zann-cosmic` — run or package the COSMIC desktop client.
- `just desktop-test` (`cd apps/desktop && bun run test`) — run Tauri frontend unit tests.
- `cd apps/desktop/src-tauri && cargo test` — run Tauri Rust backend tests.
- `just server-test-db` — run Postgres-backed server integration tests (requires Podman and `compose.test.yaml`).

---

## Commit, Issue & Pull Request Guidelines

- Use Conventional Commits for PR and issue titles: `<type>(<scope>): <subject>` (e.g., `feat(cosmic): add trash restore action`, `fix(client): bound catalog reconciliation`).
- Common scopes: `cosmic`, `desktop`, `client`, `cli`, `server`, `core`, `crypto`, `db`, `keystore`, `ffi`, `ui-core`, `ci`, `repo`.
- Breaking changes: use `!` in the title or `BREAKING CHANGE:` in the body.
- One PR per logical change; include a short summary, affected `MIG-*` or ADR references, and exact verification commands run.
- Use GitHub CLI (`gh issue list`, `gh issue view`, `gh pr create`) to track actionable work and link PRs to issues.
