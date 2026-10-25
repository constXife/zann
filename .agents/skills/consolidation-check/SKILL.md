---
name: consolidation-check
description: Review proposed Zann features, crates, modules, or diffs for capability duplication across clients, oversized files, uncoalesced MIG-* debt, cross-language logic drift (Rust/TypeScript/Swift/Kotlin), and missing subtraction. Use before adding a new surface and on T1/T2 changes.
---

# Consolidation and Anti-Bloat Review (Zann)

Local optimization pushes a change toward the path of least resistance: adding
presentation or sync rules inside a single client (`apps/cosmic` or
`apps/desktop`), growing `crates/zann-ffi/src/lib.rs` past 1,900 lines, or
leaving a legacy compatibility path alive beside its replacement. This
procedure checks a proposal or diff against Zann's three-layer architecture
(`[CORE]` → `[PRESENTATION]` → `[SHELL]`).

This skill is read-only. It does not edit code or approve releases. Normative
authority lives in [`AGENTS.md`](../../../AGENTS.md),
[`docs/Architecture.md`](../../../docs/Architecture.md),
[`docs/architecture/capabilities.md`](../../../docs/architecture/capabilities.md),
and [`config/architecture-boundaries.json`](../../../config/architecture-boundaries.json).

## Two Modes

- **Design gate (before code):** A new client feature, item type, crate, FFI
  export, or CLI command is proposed. Identify the canonical owner in
  `docs/architecture/capabilities.md`, find existing neighboring mechanisms,
  and return a short consolidation plan.
- **Change review (before commit or PR):** Inspect the base/candidate diff and
  return findings across the five gates below.

## Step 1 — Ground in the Existing Repository

Before evaluating the gates, run a bounded search (`rg`, `find`):

1. Locate the capability row in `docs/architecture/capabilities.md` and check
   whether a `MIG-001`..`MIG-008` exception in
   `config/architecture-boundaries.json` covers the touched files.
2. Search `crates/zann-client`, `crates/zann-ui-core`, `crates/zann-core`,
   `apps/cosmic`, and `apps/desktop` for existing types or helpers solving a
   neighboring problem.
3. Measure line counts of the touched non-test source files and check module
   boundaries.

## Step 2 — Five Consolidation Gates

### Gate 1 — `[CORE]` & `[PRESENTATION]` Unification over `[SHELL]` Copies

Does the change implement domain, auth, sync, config, filtering, category,
folder, field-masking, TOTP, or URL-matching policy inside a shell
(`apps/cosmic`, `apps/desktop`, `crates/zann-cli`, `crates/zann-ffi`, or future
`apps/apple` / `apps/android`)?
- If yes, move the policy to its canonical owner (`zann-client::app`,
  `zann-ui-core`, `zann-flows`, `zann-core`, or `zann-crypto`) so every native
  client and the browser host get the same behavior automatically.
- `zann-app` is frozen under `MIG-008`; never add new capabilities to it.

### Gate 2 — File and Module Budgets (No God-Modules)

Check touched files against Zann's structural budgets:

| Target | Review Signal | Hard Ceiling |
|---|---|---|
| Non-test source file | `> 400` lines | `> 1,000` lines |
| Crate / module directory | `> 30` files | — |

- Do not add new domain responsibilities or screen sub-workflows into a file
  that already exceeds `1,000` lines (such as `crates/zann-ffi/src/lib.rs`,
  `apps/cosmic/src/screens/vault.rs`, or `apps/cosmic/src/screens/settings.rs`)
  without extracting a focused submodule first.
- Keep `main.rs` and `lib.rs` limited to composition and routing.

### Gate 3 — Contract Coalescing & `MIG-*` Ratchet

- Zann is Pre-GA: when all consumers of an internal type, wire DTO, or config
  contract live in this repository, do not keep parallel versions or dual-write
  shims alive. Migrate internal callers in-place and delete the superseded path.
- If a change touches files listed under `MIG-001`..`MIG-008` in
  `config/architecture-boundaries.json` or `scripts/check-client-layering.sh`,
  it must not expand the allowlist; when a slice completes, tighten `max_matches`
  and remove the stale allowlist entry in the same change.

### Gate 4 — Cross-Language & Verification Deduplication

- **Rust ↔ TypeScript ↔ Swift/Kotlin:** Do not duplicate Rust presentation or
  validation logic in TypeScript (`apps/desktop/src/**`), Swift, or Kotlin.
  Keep schemas and rules in `zann-ui-core` / `zann-core` and project them
  through `zann-client` or `zann-ffi`.
- **Coarse-grained FFI boundary:** On `zann-ffi`, return complete view
  projections (e.g., `ItemsPage` with `ItemCounts`) rather than chatty per-row
  FFI getters that degrade SwiftUI / Jetpack Compose list scrolling.
- **In-process tests over shell scripts:** Express behavioral and state-machine
  invariants as fast `cargo test` unit/flow tests (like
  `apps/cosmic/tests/flows.rs`) rather than adding new process-spawning shell
  scripts.

### Gate 5 — Subtractive Balance

Which legacy helpers, duplicate DTOs, `MIG-*` allowlist entries, or dead UI
branches does this change make obsolete? Every change touching an existing
workflow should leave the codebase with fewer duplicate paths than it found.

## Step 3 — Report Format

Keep the output concise (under ~25 lines):

```markdown
### Consolidation Check: <scope>
**Verdict:** CONSOLIDATED | CAN UNIFY | BLOAT WARNING
**Inspected:** <files / commits>

1. **Canonical Owner & Relatives:**
   - `<crate::module>` — owning boundary in `capabilities.md`
2. **Findings:**
   - [G<1-5>, introduced|preexisting] `<path>:<line>` — <issue & concrete fix>
3. **Action Plan:**
   - **Move / Unify:** <what moves to `[CORE]` or `[PRESENTATION]`>
   - **Split:** <which oversized file/module to decompose>
   - **Delete:** <which legacy code or `MIG-*` entry to remove>
```
