# ADR 0002: Which clients exist, and in what order

- **Status:** Proposed
- **Date:** 2026-08-09
- **Context:** ADR 0001 settled *how* clients should share code. It did not ask
  *which* clients should exist, and it assumed the Tauri desktop app was the one
  that mattered. Both gaps now have answers.

## Context

### The product is already two products

The split is not a plan, it is a type:

```rust
pub enum VaultEncryptionType { Client = 1, Server = 2 }
```

| | Personal + `Client` | Shared + `Server` |
|---|---|---|
| Who can read the payload | the client only | the server too |
| Server's role | opaque storage | trusted authority holding `ZANN_SMK` |
| Evidence | `vaults/service.rs:325` gates personal vaults on `Client` | `secrets/service.rs:751` unwraps SMK → vault key → payload and returns plaintext |
| Existing clients | desktop, COSMIC | CLI (`run`, `materialize`, `template`, contexts, tokens) |

`crates/zann-server/SECURITY.md:64-65` states it plainly: service accounts are
read/list, and only for shared server-encrypted vaults. These are two trust
models, and almost every client question resolves once you ask which half it
belongs to.

### There is no administration surface at all

The server exposes `/v1/groups`, `/v1/groups/:slug/members`,
`/v1/vaults/:vault_id/members` and `/admin/policies/reload`. No client covers
any of them — not the CLI, not the desktop, not COSMIC. Adding a teammate to a
shared vault today means hand-written HTTP.

### A client with no way out

`backup_export_file` and `backup_import_file` in `crates/zann-ffi/src/lib.rs:548-562`
return `Err(CoreError::Unimplemented)`. COSMIC reaches the vault only through
that facade, so **COSMIC cannot export its own data**. The CLI cannot substitute:
it is token-based and shared-vault-only. The sole escape route is installing the
Tauri app and pointing it at the same `~/.zann` — undocumented, and squarely
inside the concurrent-access hazard the migration plan flags as unresolved.

The storage layer itself is sound: `crates/zann-db/src/lib.rs:60-64` already sets
WAL, `synchronous=Normal` and a 5s busy timeout. What is missing is not
durability but *evidence* of durability — there is no integrity check, no
verification pass, no snapshot. A user cannot confirm their data is intact, and
cannot take it elsewhere. Reluctance to store real data follows from the design,
not from timidity.

## Decision

**1. COSMIC is the reference client.** It is the maintainer's daily driver, not a
proof of concept. Where a decision trades desktop convenience against COSMIC
correctness, COSMIC wins. Practically this promotes the "COSMIC on the facade"
work, which is also what gives it create/edit/delete for the first time.

**2. Export is a precondition, not a feature.** Any client that can hold personal
data must be able to get that data out unaided. No migration step that rewrites
the local write path may land before this holds. This reorders the plan: the
backup work moves to the front.

**3. Trust needs evidence, and evidence is cheap.** Two additions, neither of
which is architectural:
- periodic consistent snapshots via SQLite `VACUUM INTO` into `~/.zann/snapshots/`;
- a `verify` operation that walks every item, decrypts it and checks
  `payload_checksum` — every primitive already exists in `zann-crypto`.

**4. A web client is scoped to the server-encrypted half, permanently.** Shared
vaults and administration only; personal vaults never appear in a browser.

The usual objection to a browser-based password manager is that the server ships
the cryptography, so it can ship malicious cryptography, and end-to-end
encryption becomes decoration. For shared vaults that objection is void — the
server holds the keys by construction, so a web UI concedes nothing that is not
already conceded. Scoping it this way is the honest boundary, not a limitation.
It is also the only client that needs no Rust core at all: plain REST over
endpoints that already exist, buildable in parallel with the core migration
without competing for it.

Its first job is administration — groups, vault membership, service accounts,
policies — not secret browsing.

**5. A browser extension is the highest-value client for the personal half**, and
it arrives as a native-messaging host. An extension cannot link a Rust library,
so the host is a small stdio binary and, for the shared core, simply one more
thin client on the facade. TOTP comes free: `zann_ui_core::generate_totp` is
already shared.

**6. The local daemon becomes a core component.** The host cannot share COSMIC's
in-process unlocked session, so either the user unlocks twice or a daemon owns
the session and both attach to it. The migration plan listed a daemon as an
optional mitigation for two clients racing over `~/.zann`; the extension makes it
load-bearing, and it resolves both problems at once:

```
zann-daemon  (session, ~/.zann, zann-app)
    ├── COSMIC UI
    ├── native messaging host → browser extension
    └── CLI and future clients
```

**7. Mobile clients come after the extension.** Autofill is where a password
manager is actually used; a mobile client without it is a viewer, and mobile
autofill is the most expensive item in the whole programme.

**8. No native macOS client.** Tauri covers macOS. If a native one is ever
wanted, it is a second target of the same Swift package, not a new client.

## Consequences

**Good.** The client list stops being a matter of taste. Each candidate is
answered by which trust model it serves and whether it needs the Rust core: the
web console needs no core and can proceed independently; the extension needs the
core but almost no UI; mobile needs everything and therefore waits. The
export-first rule turns a vague unease about data safety into two shippable
tasks.

**Bad.** Promoting COSMIC means the Tauri app stops being the pacesetter, and its
feature work will feel slower. Committing to a daemon adds a process to install,
supervise and debug on every desktop, and a new failure mode ("the daemon isn't
running") that neither client has today. The web console permanently splits the
UI story in two, and the discipline that personal vaults never appear there has
to be enforced by review, since nothing in the type system prevents it.

**Also.** ADR 0001 assumed non-Rust clients were the reason to turn on `uniffi`
binding generation. On this decision the native-messaging host — a Rust binary —
arrives first, so bindings stay valuable but stop being urgent. What becomes
urgent instead is facade completeness, because the host and COSMIC both live
entirely on it.

## Plan

1. Move `services/backup.rs` into the shared core and implement the two facade
   stubs. Only three call sites touch the OS (`rfd::FileDialog`); everything else
   already takes a path. COSMIC gains export.
2. Add snapshots (`VACUUM INTO`) and `verify`.
3. Proceed with the safety net and the sync reconciliation from ADR 0003, in that
   order — both now sit behind a working export.
4. Put COSMIC fully on the facade; it gains create, edit and delete.
5. Native-messaging host plus daemon; browser extension for password and TOTP
   autofill.
6. Web administration console over the shared half.
7. Revisit mobile.

## Alternatives considered

**A web UI over personal vaults too.** It is what Bitwarden does and it is the
single most criticised part of that product. Rejected: it would put the
end-to-end guarantee at the mercy of every page load, for a convenience the
extension serves better.

**An extension that talks to the server directly instead of a local host.**
Simpler to ship, but personal vaults are client-encrypted, so the extension would
need the master key in the browser, and offline-first would be lost. Rejected.

**Dropping COSMIC and standardising on Tauri.** It would remove a client and some
duplication. Rejected: it is the maintainer's daily driver, and after the
facade work its marginal cost is roughly 1.5k lines.

**Treating the shared half as the whole product** (a Vault competitor, no personal
vaults). Coherent, and the server is arguably better prepared for it than for the
consumer half. Rejected for now — but noted, because continuing to fund both
halves is a standing cost and this ADR does not settle it forever.
