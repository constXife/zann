# ADR 0005: Versioned runtime secret delivery profiles

- **Status:** Accepted
- **Decision date:** 2026-08-29
- **Scope:** `zann-client::delivery`, `zann-cli delivery`, and future deployment
  adapters
- **Extends:** [ADR 0004](0004-machine-secret-plane.md) §5

## Context

ADR 0004 deliberately shipped the machine-secrets API and coordinated rotation
before reopening runtime delivery. The resulting CLI plane established three
useful facts:

- machine consumers need exact secret paths far more often than broad tag or
  pattern selection;
- `batch/get` gives one bounded, validated read for a service-sized set of
  values;
- atomically replacing individual files is safe for refresh, but it does not
  let a consumer observe several related credentials as one configuration.

The next contract must be usable by systemd, containers and local launchers
without making any one platform the owner of secret selection, path collision
or serialization policy. It must also preserve the delivery principles from
ADR 0004: deployment configuration contains references rather than values,
credential files are preferred, and plaintext stdout is not a sink.

## Decision

### 1. The profile is a small, versioned and value-free artifact

Version 1 is YAML with this closed schema:

```yaml
version: 1
vault: infra
files:
  - secret: services/web/database
    target: database-password
  - secret: services/web/session-key
    target: session-key
```

Unknown fields fail parsing. A profile contains one explicit vault and between
1 and 64 exact `secret` to relative `target` mappings. Both source and target
collisions are rejected. Traversal, absolute targets, hidden target segments,
control characters and overlong paths are rejected before network I/O.

The closed, single-batch limit is intentional. Selectors would make a profile's
authority and output change when unrelated items are created. Multiple vaults
would make a complete observation depend on multiple authorization domains and
requests. A larger profile needs composition by the deployment layer, not a
larger implicit transaction.

Profiles contain no generation policy and perform no `ensure` or write. Secret
provisioning is a separate deployment step. Applying a delivery profile is a
read-only operation and fails if any referenced value is unavailable.

### 2. Delivery policy has one DB-free owner

`zann-client::delivery` owns the schema, normalization, bounds and collision
policy. It is a small feature independent of local storage, sync, keyrings and
the full `app` feature. `zann-client::app` composes that feature, while the
remote-only CLI consumes the same owner without pulling the local application
graph.

Adapters own only profile input, authentication, platform paths and the
concrete sink. They must not reinterpret the schema or add implicit selectors
or output modes.

### 3. The first sink publishes complete generations

`zann delivery apply --profile PROFILE --out ROOT` resolves every reference
with one `secrets/batch/get`, validates the whole response, writes a new private
generation and only then publishes it:

```text
ROOT/
  current                         # regular file: generation UUID + newline
  generations/
    019.../
      database-password
      session-key
```

The generation directory and every nested directory are `0700` on Unix; value
files and `current` are `0600`. Targets are created without following symlinks,
bounded to 256 KiB each, synced and atomically replaced inside the unpublished
generation. Replacing `current` is the commit point. `current` is deliberately
a regular file rather than a symlink.

A consumer reads `current` once at launch and then uses that fixed generation
path for all credentials. Published generations remain immutable. The CLI
retains two complete generations by default, configurable from 1 to 10, and
prunes older UUID-named generation directories after publication. Failure to
prune does not roll back an already committed generation and is reported as a
warning.

The command prints only the generation UUID. Values and value-derived hashes
never enter argv, environment variables, logs, audit events, the profile or
stdout.

### 4. Platform activation stays explicit

The generic sink does not restart a service. A platform adapter must
declare how a new generation becomes active and must keep that action after
successful publication.

The first systemd adapter is implemented by the exported
`nixosModules.zann-delivery`. It generates value-free profiles in the Nix
store, receives the service-account token through its own `LoadCredential=`,
and installs a runtime drop-in that points directory-form `LoadCredential=` at
one exact immutable generation. Only after `daemon-reload` does it explicitly
restart the declared unit, because reload does not recreate systemd's credential
directory. A required, retained bootstrap oneshot
gates the initial target start; a separate refresh service and optional timer
cannot enter a dependency cycle with the target.

The systemd sink accepts only flat credential names and caps their aggregate
payload at 1 MiB. Exact unchanged generations are reused without a
secret-derived hash, avoiding timer-driven restarts when values did not change.
It never silently falls back to environment variables.

### 5. Online resolution is required in version 1

There is no offline cache. Applying a profile while Zann is unavailable fails
without changing `current`, so the last complete retained generation remains
addressable. Automatically reusing it would blur a fresh resolution with stale
material and hide revocation. Boot-time availability, cache encryption and
cache expiry require a later ADR before unattended early-boot delivery can be
claimed.

## Consequences

### Positive

- Related credentials become observable as one complete generation.
- Deployment repositories can commit and review references without committing
  values.
- Future adapters share one schema and validation policy.
- A failed fetch or partial batch response leaves the previously published
  generation current.

### Costs and limitations

- A profile is capped at 64 files and one vault.
- Retained generations deliberately keep previous plaintext values on disk;
  choose retention 1 where local rollback is not required.
- Publication does not revoke values already held by a process and does not
  activate a service.
- No offline or early-boot availability guarantee exists.
- The output root must be private and writable by the adapter; sharing it
  directly with a less-trusted workload would also grant access to retained
  generations.

## Rejected alternatives

**Put values in a NixOS module or generated unit.** Rejected because Nix and
unit definitions are persistent configuration surfaces, not secret sinks.

**Publish files directly at stable target paths.** Rejected because consumers
could observe a mixture of old and new related values.

**Use an atomic `current` symlink.** Rejected for the first sink so its trusted
control path does not need a symlink exception. A regular pointer also makes a
consumer's read-once requirement explicit.

**Implicitly reuse the last generation on network failure.** Rejected because
successful fresh resolution and stale fallback need different policy and
observability.
