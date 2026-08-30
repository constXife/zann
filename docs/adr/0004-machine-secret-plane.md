# ADR 0004: The machine secret plane, rotation hooks and delivery scope

- **Status:** Accepted
- **Decision date:** 2026-08-29
- **Scope:** `crates/zann-server` secrets and rotation domains, `crates/zann-cli`,
  `crates/zann-client::app`, and the documentation that exposes them
- **Replaces:** an unreleased draft of ADR 0004 ("Runtime secret delivery and
  NixOS integration"), which was never committed. Its NixOS/systemd design is
  deferred to a later ADR; the reasoning is recorded under *Rejected
  alternatives*.

## Context

### The product boundary this ADR defends

Zann is a self-hosted manager for people and small teams that also has to hand
secrets to machines. That second half places it between two established
products, and the gap between them is the position worth holding:

- **Bitwarden** ships machine secrets as a *separate* product (Secrets
  Manager), and the dominant self-hosted Bitwarden server does not implement
  it. Self-hosted users therefore run a password manager and a second,
  unrelated secret system side by side.
- **Vault / OpenBao** win decisively on dynamic secrets, leases, TTLs and
  engines. That is also what makes them heavy to operate.

Zann's position is the narrow one between them: **static secrets with
versions, audit and hooks, served to machines from the same self-hosted server
that holds the team's passwords.** Everything in this ADR follows from
defending that sentence, in both directions — it must be reachable enough to
replace the second system, and it must not grow into an engine framework.

### The capability already exists and is unreachable

An audit of the server for this decision found that most of the machine plane
is implemented, tested, and invisible.

Present and working:

- a machine-facing secrets API in
  [`domains/secrets/http/v1`](../../crates/zann-server/src/domains/secrets/http/v1/mod.rs):
  metadata-only `GET /v1/vaults/{id}/secrets`, `GET`/`PUT
  /v1/vaults/{id}/secrets/*path`, `POST .../secrets/ensure`, `POST
  .../secrets/rotate`, `POST .../secrets/batch/ensure`, and `POST
  .../secrets/batch/get`;
- server-side generation policies in
  [`domains/secrets/policies.rs`](../../crates/zann-server/src/domains/secrets/policies.rs);
- service-account scopes with vault and path-prefix rules, enforced on both the
  item and secret paths, including explicit `rotate` and `read_previous`
  permissions;
- an audit event for every read, write and rotation in
  [`infra/audit.rs`](../../crates/zann-server/src/infra/audit.rs);
- a complete two-phase rotation state machine on shared items —
  `rotate/start`, `rotate/candidate`, `rotate/commit`, `rotate/abort`,
  `rotate/recover`, `rotate/status` — with `rotating`/`stale` states, an
  expiry, a recovery window and zeroized candidate values;
- addressable version history at `/v1/shared/items/{id}/history/{version}`.
- a canonical `zann-client` secrets/rotation transport and native CLI commands,
  including `zann rotate --exec` and `secret get --previous`.

Still absent:

- deployment-profile artifacts and platform delivery adapters, intentionally
  deferred to phase 5.

An API that no shipped client calls and no document mentions is, from a user's
position, an API that does not exist. The withdrawn draft proposed a new
delivery layer — environment profiles, generation publication, a NixOS module —
on top of this. That is the wrong order: it adds a consumer for a capability
nobody can reach today.

### The plane split is already correct

[`VaultPlane`](../../crates/zann-client/src/sync/model.rs) already distinguishes
`PersonalClient` from `SharedServer`. Personal vaults are client-encrypted and
the server cannot read them; shared server-encrypted vaults are the only plane
a machine can be served from. This ADR makes that split a product statement
rather than an implementation detail.

## Decision

### 1. Zann serves static secrets, and states so

Zann stores, versions, audits and serves **static** secret values, and provides
hooks so operators can coordinate their own rotation. Generating and revoking
credentials inside external systems is the operator's script, not a Zann
feature.

Explicitly out of scope, permanently unless a future ADR reverses it:

- dynamic secrets, leases and TTL-bound credentials;
- PKI, transit, SSH-CA or other secret engines;
- a Kubernetes operator or admission injector;
- built-in per-provider rotators (Postgres, AWS, Cloudflare, …).

This boundary belongs in `README.md` as one sentence, because the difference
from both Bitwarden and Vault is otherwise not obvious to a reader.

### 2. Only the shared server-encrypted plane is machine-readable

A service account may read from shared, server-encrypted vaults only. Personal
client-encrypted vaults require an unlocked local session and are never served
to an unattended workload. Any future automated access to a personal vault is a
separate, explicitly enabled feature with its own ADR, because it requires
storing an unlock key on the machine.

### 3. The existing secrets API is the canonical machine surface

There is one machine-facing API and it is the one that exists. No client,
adapter or integration introduces a parallel surface.

Consequences that are binding:

- the CLI gains commands over it — `get`, `set`, `ensure`, `rotate`, `list` —
  rather than reimplementing resolution over the items API;
- `zann materialize` migrates to `secrets/batch/get`, removing the per-item
  request fan-out;
- `docs/Server.md` and `docs/CLI.md` document the API, the scope syntax and the
  rotation state machine with runnable examples. **Documentation is part of the
  capability, not an afterthought to it**; an undocumented endpoint is treated
  as unshipped for release purposes.

### 4. Zann owns the rotation state machine; the operator owns the effect

Rotation is split at the only line that can be drawn safely:

- **Zann owns** the state machine, the generated candidate, the version bump,
  the expiry, the recovery window and the audit record. This is implemented.
- **The operator owns** the external effect — applying the new value to a
  database, a provider API or a config system.

To make operator-owned rotation practical, the following is added.

**An exec hook.** `zann rotate <path> --exec <program>` performs
`start` → run program → `commit` on success, `abort` on failure. The contract:

- the previous and candidate values are passed to the program on **stdin as a
  single JSON document**, never in `argv` and never in the environment;
- a non-zero exit status, a timeout, or a signal aborts the rotation;
- the hook timeout is bounded by the rotation's `expires_at`, so a hung hook
  cannot hold a rotation open indefinitely;
- hook stdout and stderr are forwarded to the operator's terminal but never to
  an audit event, because a hook may echo the value it was given.

**A grace window for readers.** A commit must not create a gap in which
consumers holding the previous value are already rejected while they have not
yet restarted. Readers may request the immediately previous version during the
recovery window through an explicit selector on the read path. Note the
existing cap: `ITEM_HISTORY_LIMIT = 5` versions are retained, which is
sufficient for a grace window and is not a general version store.

**Two rotation paths, named for what they are.** The single-shot
`POST /v1/vaults/{id}/secrets/rotate` replaces a value with no external
coordination and accepts service accounts. At decision time, the two-phase item
rotation rejected service accounts in every handler — `rotate/start`,
`rotate/candidate`, `rotate/commit`, `rotate/abort`, `rotate/recover` and
`rotate/status` all returned `403`. That asymmetry made unattended two-phase
rotation impossible by construction.

The decision: lift that restriction only behind an explicit, deny-by-default
`rotate` scope on the service account. A scheduled rotation is a high-value
target; it does not inherit read or write authority. Force-abort remains
admin-only even when a service account has `rotate`.

### 5. Runtime delivery keeps its principles and loses its scope

The withdrawn draft's security principles are retained, because they are
correct and because they describe defects in code that is already shipped:

- deployment configuration holds **references**, never values; values are
  resolved at launch;
- credential files are the preferred sink for services; process environment and
  dotenv are compatibility modes that an adapter may never silently select;
- plaintext stdout is not a materialization mode;
- the file sink is a security boundary: private directories and files, atomic
  publication, no traversal or symlink following, bounded size, and no secret
  values or secret-derived hashes in logs.

These capabilities were deferred from this ADR until §3 and §4 shipped. ADR
0005 subsequently implemented the versioned delivery-profile artifact,
generation-level publication, timer refresh and the first NixOS/systemd
adapter. macOS/Windows/container adapters and an encrypted offline cache remain
outside this ADR.

What remains in scope for delivery is the existing `zann run` and
`zann materialize`, corrected under §6.

### 6. Existing CLI defects are in scope for this ADR

These entered the ADR as live defects in shipped commands. Their current
implementation status is tracked here:

- **Resolved:** [`render_fs.rs`](../../crates/zann-cli/src/modules/shared/render_fs.rs)
  now creates private staging files, rejects symlinks, syncs file and directory,
  and atomically replaces the destination without an unlink window.
- **Resolved:** `zann materialize` requires `--field`; it no longer has an
  implicit whole-payload projection that could write TOTP seeds or recovery
  codes beside the intended value.
- **Resolved:** token values are not accepted as CLI arguments. Both the global
  token input and `config set-context` use `--token-file`; the old `--token`
  interface and `ZANN_TOKEN` alias were removed as a clean cut before release.

## Consequences

### Positive

- The capability Zann already paid for becomes usable, which is the cheapest
  available increase in the product's value.
- The self-hosted gap left by Vaultwarden — passwords and machine secrets in
  one server — is addressed without adopting Vault's operational weight.
- Operator-written rotation becomes safe by construction: a failed hook aborts
  rather than leaving a committed value that no external system accepts.
- The delivery principles survive without committing to a platform integration
  before the underlying capability has a single real user.

### Costs and limitations

- Field-level references remain client-side hygiene, not a security boundary:
  the API returns whole item payloads, so a scope grants access to every field
  of a matched item. This must be documented rather than implied away.
- Revocation does not reach running processes. A process holding a secret keeps
  it until it restarts; only the declared reload/restart makes a rotation
  effective.
- Retaining five versions bounds the grace window; it is not a general history
  store and cannot serve long rollbacks.
- Zann remains, by the README's own statement, unaudited and not recommended
  for production. Serving service credentials raises the cost of a defect
  relative to storing passwords, and this positioning must stay honest in the
  documentation this ADR requires.

## Implementation plan

Each phase is independently useful and independently reviewable.

1. **Document what exists.** The secrets API, scope syntax, generation policies
   and the rotation state machine, with working examples. The generated
   `docs/openapi.json` already carries the endpoint schemas; what is missing is
   prose that tells a reader the plane exists and how to drive it. This phase
   writes no feature code and is the highest-leverage one.
2. **Fix the shipped defects** from §6: hardened file sink with private modes,
   `O_NOFOLLOW`, `fsync`, atomic replacement without an unlink window; explicit
   sensitive-field selection; token-file-only CLI and context provisioning.
3. **Give the CLI the secrets plane**: `zann secret get/set/ensure/rotate/list`
   over the existing API, and `materialize` migrated to `secrets/batch/get`.
   This phase is implemented. Listing uses a dedicated metadata-only secrets
   endpoint, and `materialize` uses it for cursor-aware discovery before
   bounded batch reads. `set` accepts values only from stdin or a bounded UTF-8
   file, never from argv.
4. **Rotation hooks**: `--exec` with the stdin/exit-status contract, the
   reader-side grace selector, and the deny-by-default `rotate` scope for
   service accounts. This phase is implemented. Hook values cross only stdin;
   Unix hook process groups are terminated before abort on timeout/interrupt;
   commit failures after a successful external effect remain recoverable.
   The start response binds the candidate to `previous_version`, and the CLI
   aborts before executing the hook if that version no longer matches its
   previous-value read.
   `GET .../secrets/*path?version=previous` exposes only the immediately
   previous version within the configured retention window, and service
   accounts require the explicit `read_previous` permission.
5. **Re-open delivery**: only after phases 1–4 are in use, propose the profile
   artifact and platform adapters in a new ADR, informed by how the CLI plane
   was actually used. This phase is implemented by
   [ADR 0005](0005-runtime-secret-delivery-profiles.md): it defines the v1
   profile, the generation-publishing file adapter and NixOS/systemd activation.
   Adapters for other platforms remain follow-up work.

## Rejected alternatives

**Build the NixOS/systemd module first (the withdrawn draft).** Rejected on
sequencing, not on merit. The design was sound, but it adds a consumer for a
capability that no shipped client can reach and no document describes. Its
strongest requirements — references not values, credential files over
environment, a hardened sink — are retained in §5. Its remaining scope returns
once the plane beneath it is real. The draft also treated the encrypted offline
cache as deferrable, which understated a genuine boot-time availability
problem; that must be re-examined when delivery is re-opened.

**Dynamic secrets with leases.** Rejected. It is the feature that separates
Vault from everything else and the reason Vault is heavy. Adopting it would
abandon the position in §1 and cannot be done credibly by an unaudited project.

**Built-in rotators per provider.** Rejected. Each rotator is an integration
with its own auth, error semantics and failure modes, and the set never
converges. The exec hook lets an operator express the same thing in a few lines
while Zann keeps ownership of the part that must be transactional.

**A second, "simpler" machine API beside `/v1/vaults/{id}/secrets`.** Rejected
for the same reason ADR 0001 rejected client forks: two surfaces drift, and the
one with tests is not necessarily the one clients use.

**Serving personal client-encrypted vaults to service accounts.** Rejected for
this ADR. It requires an unlock key resident on the machine, which changes the
product's central guarantee and deserves its own decision.
