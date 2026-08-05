# ADR 0001: One client core, headless flows, shared presentation

- **Status:** Proposed
- **Date:** 2026-08-05
- **Context:** adding the COSMIC client (`apps/cosmic`) surfaced how much a new
  client has to re-implement.

## Context

Every client is supposed to sit on a shared Rust core. In practice each one sits
on a different stack:

| client | builds on | own logic |
|---|---|---|
| `apps/desktop` (Tauri) | `zann-core`, `zann-db`, `zann-keystore`, `zann-ui-core` | 9378 lines in `src-tauri/src`, including its own auth and sync |
| `apps/cosmic` (libcosmic) | `zann-ffi` → `zann-client` → `zann-core`, `zann-db` | 2100 lines, of which ~800 are widgets |
| `crates/zann-cli` | `zann-core` only | 3170 lines, including its own HTTP transport (153) and token handling (407) |

`zann-client` is used by `zann-ffi` and `apps/cosmic`. `zann-ffi` is used by
`apps/cosmic` alone. Neither is used by the desktop app or by the CLI.

### The desktop services are a fork of `zann-client`

The same files exist twice, with the same function names (`remote_sync`,
`remote_reset`, `sync_reset_cursor`) and a structure that lines up:

| file | `apps/desktop/src-tauri/src/services` | `crates/zann-client/src` | lines that differ |
|---|---|---|---|
| `auth.rs` | 456 | 439 | |
| `auth_oidc.rs` | 541 | 476 | 257 |
| `auth_password.rs` | 342 | 333 | 51 |
| `sync.rs` | 579 | 556 | 71 |
| `sync_helpers.rs` | 700 | 589 | |

Roughly 2600 lines duplicated, already drifting — half of `auth_oidc.rs` no
longer matches. A fix to the OIDC flow has to be written twice, and today it is
not.

### What a new client re-implements above the core

Building `apps/cosmic` showed three more layers with no shared home:

1. **The connect flow.** Probe the server → pick an auth method → password or
   SSO → confirm a changed fingerprint → master password → first sync. This is a
   state machine with nothing toolkit-specific in it. It exists in the desktop
   services, it existed in the (now removed) Qt PoC, and it was written a third
   time as `apps/cosmic/src/screens/connect.rs` — 512 lines. The same goes for
   the smaller "which screen comes first" decision derived from `app_status`.

2. **The item detail presentation model.** `zann-ui-core` owns the list side
   (categories, folder tree, filter, TOTP generation) but not the card: field
   order, human labels, which fields are masked by default, and parsing
   `otpauth://` URIs live in `useItemDetails.ts` and again in
   `apps/cosmic/src/screens/detail.rs`. They have already diverged — the desktop
   orders fields by the type schema, COSMIC by a hard-coded list, so the same
   item is presented differently in the two clients.

3. **Labels and icons.** `schemas/ui_categories.json` hands out i18n keys
   (`nav.logins`) and abstract icon names (`key`, `doc`). Every client carries
   its own key-to-English table and its own icon mapping. That is data
   pretending to be code.

## Decision

Treat "one core, many clients" as four layers with explicit owners, and hold
new clients to them.

1. **One client core.** `zann-client` is the only implementation of auth, token
   handling and sync; `zann-ffi` is the only facade over the local vault. The
   desktop services move onto it and the fork is deleted. The CLI keeps its
   server-only nature but takes its transport and token handling from the same
   crate.

2. **Headless flows.** The connect and session flows become state machines next
   to `zann-ui-core`: `handle(Event) -> (State, Vec<Effect>)`, where an `Effect`
   names a backend operation to run. No toolkit, no async runtime, no `Task`
   type. Clients render the state and execute the effects with whatever their
   framework uses, and the flows are testable without a compositor.

3. **Presentation in `zann-ui-core`.** The crate already owns what the list
   shows; it also takes the card: an `ItemDetailView` whose fields arrive
   ordered, labelled, masked, with TOTP parameters resolved. Clients render, they
   do not decide.

4. **Labels and icons as data.** A translation catalogue ships next to
   `schemas/ui_categories.json`; icon names map to a toolkit through a table the
   client declares once, not per call site.

What stays per client: widgets, layout, and platform integration (clipboard,
biometrics, tray, file dialogs). In `apps/cosmic` that is about 800 of 2100
lines, and that is the right shape for a client.

## Consequences

**Good.** A feature or a fix lands once. A new client is "render N screens and
map the effects" — on the COSMIC evidence, closer to 600–800 lines than 1300.
Clients cannot silently diverge in behaviour, the way the desktop and
`zann-client` OIDC flows have. The flows and the presentation model get unit
tests that no client can bypass; `apps/cosmic/tests/flows.rs` is the pattern.

**Bad.** Step 1 is a large, risky change to the client that people actually use,
touching auth and sync. It should land behind the existing DB-backed tests and
in reviewable pieces, not as one commit. Steps 2 and 3 move code that currently
lives close to its UI further away, which costs a little indirection.

**Also.** `zann-ffi` is built on `uniffi` 0.28 but nothing generates bindings —
`apps/cosmic` links it as a plain rlib. If the Swift and Windows clients in
`docs/Architecture.md` are real, turning binding generation on is the mechanism,
and it only pays off once step 1 makes the facade complete.

## Plan

1. Reconcile `apps/desktop/src-tauri/src/services/{auth,auth_oidc,auth_password,sync,sync_helpers}.rs`
   with `crates/zann-client`, decide per difference which side is right, and
   delete the copy.
2. Extract the connect and session flows from the desktop and `apps/cosmic` into
   a shared headless crate; both clients adopt it.
3. Move the item detail presentation model into `zann-ui-core`; settle the field
   ordering difference in favour of the type schema.
4. Move the label catalogue and icon mapping into `schemas/`.
5. Only then consider generating `uniffi` bindings for a non-Rust client.

## Alternatives considered

**Leave it and copy per client.** This is the status quo, and the measured drift
between the two OIDC implementations is what it costs. Rejected.

**Share the UI instead of the logic** (one toolkit everywhere, or a web view in a
shell). It would remove the duplication, but it gives up native clients, which is
the point of the COSMIC and Qt experiments and of the memory numbers in
`apps/cosmic/README.md`. Rejected.

**Put everything behind `zann-ffi` including the flows.** Tempting, but the flows
need to drive the UI, and a `uniffi` boundary makes state machines awkward to
observe. Keeping the flows as a plain Rust crate, with `zann-ffi` for the vault
operations, keeps both usable.
