---
title: Machine Secrets
description: Serving secrets to services and automation over the HTTP API, including generation policies and coordinated rotation.
---

Zann serves secrets to unattended workloads — CI jobs, deployment tooling and
services — from shared, server-encrypted vaults. This page documents that
plane: how a machine authenticates, what it may read, the HTTP API it calls,
how values are generated, and how a rotation is coordinated with the external
system that consumes the secret.

The decision that defines this surface, its boundaries and its non-goals is
[ADR 0004](adr/0004-machine-secret-plane.md).

## What a machine can and cannot read

Zann has two vault planes:

| Plane | Encryption | Machine-readable |
|---|---|---|
| Personal | Client-side; the server never holds the key | **No** |
| Shared | Server-side, with the server master key | Yes |

A service account can only reach **shared, server-encrypted** vaults. A request
against a personal vault fails with `400 vault_not_server_encrypted`. Reading a
personal vault without a human present would require an unlock key resident on
the machine, which is deliberately not offered.

Within a shared vault, this API addresses items of type `secret` only. Such an
item holds exactly two fields — `value` and `policy` — plus an optional `meta`
string map. Items of other types are invisible here and return `404`; use the
shared-items API for those.

## Authenticating

Machines authenticate with a **service account token** (`zann_sa_…`) and
exchange it for a short-lived access token.

Create the token on the server:

```bash
zann-server token create ci-prod infra:/ read
```

The arguments are `<name> <vault:prefixes> [ops]`. Write the token straight to a
file rather than through a terminal when provisioning a host:

```bash
zann-server provision ensure-token yogg-grafana \
  infra:rlyeh/yogg/grafana read \
  --write-token-file /run/secrets/yogg-zann-token
```

Exchange it for an access token:

```bash
curl -sS https://zann.example.com/v1/auth/service-account \
  -H 'content-type: application/json' \
  -d "{\"token\":\"$(cat /run/secrets/yogg-zann-token)\"}"
```

```json
{
  "access_token": "…",
  "expires_in": 3600,
  "service_account_id": "…",
  "owner_user_id": "…",
  "vault_keys": []
}
```

The access token lives for one hour by default
(`ZANN_ACCESS_TOKEN_TTL_SECONDS`); a long-running agent must exchange again
rather than cache it indefinitely.

Every subsequent request carries `Authorization: Bearer <access_token>`. Keep
the long-lived `zann_sa_…` token in a file with private permissions; never pass
it on a command line, where it is visible to every local user through `ps`.

## Scopes

A service account's authority is a list of scope strings. `zann-server token
create` builds them for you, but the format is worth knowing because it is what
appears in the database and in audit reasoning:

```text
<vault>:<permission>
<vault>/prefix:<path>:<permission>
```

`<vault>` is a vault UUID, a slug, `tag:<tag>`, or `pattern:<glob>` matched
against the slug. The permission is the last colon-separated segment.

| Op | Grants |
|---|---|
| `read` | reading and listing secrets |
| `write` | creating, updating, ensuring and single-shot rotation |
| `read_history` | listing an item's version history |
| `read_previous` | reading a specific historical version |
| `rotate` | driving coordinated `rotate/*` state transitions; does not grant force-abort |

Prefix rules match a path exactly or any path beneath it: `services` matches
`services` and `services/api`, but not `services-old`. A token with only
prefixed rules cannot perform an unprefixed listing of the whole vault.

Examples:

```bash
# read everything in the infra vault
zann-server token create ci-prod infra:/ read

# read and write one subtree
zann-server token create deployer infra:services/web read,write

# read two subtrees, expiring in 30 days
zann-server token create audit infra:services,platform read --ttl 30d
```

Scopes are the security boundary at **item granularity**. The API returns a
whole secret item, so a scope that matches a path grants every field of that
item. Choose paths accordingly.

## Secrets API

All paths below are relative to the server root. `{vault}` accepts a vault UUID
or slug. `{path}` is the item path; a leading `/` is optional on input and
always present in responses.

### List secret metadata

`GET /v1/vaults/{vault}/secrets` lists only active items of type `secret`. It
does not decrypt payloads and returns no value, policy, or user metadata.

```bash
curl -sS -G -H "Authorization: Bearer $ACCESS_TOKEN" \
  --data-urlencode 'prefix=services/web' \
  --data-urlencode 'limit=50' \
  https://zann.example.com/v1/vaults/infra/secrets
```

```json
{
  "secrets": [
    {
      "path": "/services/web/database",
      "version": 3,
      "updated_at": "2026-08-29T12:00:00Z"
    }
  ],
  "next_cursor": "…"
}
```

The default page size is 50 and the maximum is 100. `next_cursor` is opaque;
send it back as the `cursor` query parameter. A prefix-scoped service account
must request a prefix inside its granted subtree. Listing the whole vault with
only a prefix scope fails with `403`.

The CLI equivalent is:

```bash
zann secret list --vault infra --prefix services/web --format json
```

### Read one secret

```bash
curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://zann.example.com/v1/vaults/infra/secrets/services/web/database
```

```json
{
  "item_id": "…",
  "path": "/services/web/database",
  "vault_id": "…",
  "value": "…",
  "policy": "default",
  "meta": { "owner": "platform" },
  "version": 3
}
```

`item_id` is the stable identifier used by the coordinated rotation endpoints.
To read only the immediately previous value during the configured grace
window, use an explicit selector and a `read_previous` scope:

```bash
curl -sS -H "Authorization: Bearer $ACCESS_TOKEN" \
  'https://zann.example.com/v1/vaults/infra/secrets/services/web/database?version=previous'

zann secret get services/web/database --vault infra --previous
```

There is no implicit fallback from current to previous: readers must ask for
the previous version deliberately. The selector stops returning the version
after `rotation.stale_retention_seconds` and never exposes older history.

### Write one secret

```bash
curl -sS -X PUT -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  https://zann.example.com/v1/vaults/infra/secrets/services/web/database \
  -d '{"value":"…","policy":"default","meta":{"owner":"platform"}}'
```

The response carries `created: true` when the item did not previously exist and
`created: false` when it was updated.

The CLI exposes the same operation without placing the new value in argv:

```bash
zann secret set services/web/database --vault infra \
  --value-file /run/secrets/new-database-password
```

Use `--stdin` instead when the producer writes the exact UTF-8 value to a pipe.

### Create if absent

`ensure` is the idempotent provisioning primitive: it creates the secret with a
server-generated value if it is missing, and otherwise returns the existing one
untouched.

```bash
curl -sS -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  https://zann.example.com/v1/vaults/infra/secrets/ensure \
  -d '{"path":"services/web/database","policy":"strong"}'
```

If the secret exists but was generated under a different policy, the request
fails with `409 policy_mismatch` and reports both policies in `details`. It
does **not** silently regenerate the value.

### Single-shot rotation

`rotate` replaces the value with a freshly generated one and advances the
version. It performs no coordination with any external system — see
[Coordinated rotation](#coordinated-rotation) when the value must also be
changed somewhere else.

```bash
curl -sS -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  https://zann.example.com/v1/vaults/infra/secrets/rotate \
  -d '{"path":"services/web/database"}'
```

The response includes both `version` and `previous_version`.

The equivalent CLI command prints the new value by default; JSON output also
shows both version numbers:

```bash
zann secret rotate services/web/database --vault infra \
  --policy strong --format json
```

### Batches

`batch/get` and `batch/ensure` take up to **64** paths per request and are the
right way to populate a whole service's configuration in one round trip.

```bash
curl -sS -X POST -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'content-type: application/json' \
  https://zann.example.com/v1/vaults/infra/secrets/batch/get \
  -d '{"paths":["services/web/database","services/web/session-key"]}'
```

```json
[
  { "path": "services/web/database", "status": "ok", "secret": { "…": "…" } },
  { "path": "services/web/missing", "status": "error", "error": { "error": "not_found" } }
]
```

A batch returns `200` with per-entry results; individual failures do not fail
the request. Exceeding the count, or an aggregate response larger than 16 MiB,
returns `413 batch_too_large`. Note that `batch/ensure` is not atomic: entries
before a failure are already written.

`zann materialize --field value` discovers paths through the metadata-only
secret list and uses `batch/get` in chunks of 64. It validates every entry in a
chunk before publishing any file from that chunk; earlier successful chunks
are not rolled back if a later chunk fails.

For multi-file service configuration, `zann delivery apply` uses the versioned
value-free profile defined by
[ADR 0005](adr/0005-runtime-secret-delivery-profiles.md). Unlike `materialize`,
it requires exact paths and publishes the whole set behind one generation
pointer, so a consumer does not observe a mixture of old and new credentials.
It is online-only and does not restart or reload the consuming service.

The exported NixOS module layers explicit activation on top of this primitive:
it pins a concrete generation in a runtime systemd `LoadCredential=` drop-in,
then restarts the declared unit only when the generation changed. A reload is
insufficient because systemd does not recreate the service credential directory.
See [NixOS Secret Delivery](NixOS-Delivery.md).

### Errors

| Status | `error` | Meaning |
|---|---|---|
| `400` | `vault_not_server_encrypted` | The vault is personal/client-encrypted |
| `400` | `unknown_policy` | The named generation policy is not configured |
| `400` | *(path codes)* | The item path is empty, too long or malformed |
| `401` | — | Missing, expired or invalid access token |
| `403` | — | The scope does not cover this vault, path or operation |
| `404` | — | No active `secret` item at that path |
| `409` | `policy_mismatch` | `ensure` requested a policy the existing secret was not generated with |
| `409` | `path_in_use` | A non-`secret` item already occupies that path |
| `409` | `concurrent_create` | A competing `PUT` won the race; re-read before retrying |
| `413` | `batch_too_large` | Too many entries or too large a response |
| `500` | `smk_missing` | The server master key is not configured |

## Generation policies

Generated values — `ensure`, both forms of rotation — follow a named password
policy. Policies are configured server-side:

```yaml
secrets:
  policies_file: /etc/zann/secret-policies.yaml
  default_policy: "default"
```

```yaml
# /etc/zann/secret-policies.yaml
default_policy: default
policies:
  default:
    length: 32
    min_lowercase: 1
    min_uppercase: 1
    min_digits: 1
  strong:
    length: 48
    min_lowercase: 2
    min_uppercase: 2
    min_digits: 2
    min_symbols: 2
    symbols: "!@#$%^&*()-_=+"
  database:
    # some engines reject symbols in passwords
    length: 40
    min_digits: 4
```

A policy is rejected if `length` is zero, if the minimums sum to more than
`length`, or if `min_symbols` is positive while `symbols` is empty. The policy
name is stored with the secret, which is what lets `ensure` detect a mismatch
later.

## Coordinated rotation

Replacing a stored value is easy; keeping it in step with the database or
provider that must accept it is the hard part. For that, shared items expose a
two-phase rotation with an explicit lock, an expiry and a recovery window.

### The state machine

```text
idle ──start──▶ rotating ──commit──▶ idle (new version)
                   │  │
                   │  └──abort──▶ idle (value unchanged)
                   │
              lock expires
                   ▼
                 stale ──recover──▶ read the candidate again
                       ──abort ────▶ idle
```

`start` generates and stores an encrypted **candidate** without touching the
live value, and takes a lock. While the lock is held the candidate can be read
repeatedly, so a crashed rotator can resume. `commit` promotes the candidate to
the live value and advances the version; `abort` discards it and leaves the
live value untouched.

If the lock expires before a commit, the rotation becomes `stale` rather than
vanishing — the candidate may already have been applied externally, so it is
retained for `recover` until the retention window ends.

### Endpoints

| Endpoint | Purpose | Role action |
|---|---|---|
| `POST /v1/shared/items/{id}/rotate/start` | Generate a candidate and lock | `rotate_start` |
| `GET /v1/shared/items/{id}/rotate/status` | State, timestamps, abort reason | `rotate_status` |
| `POST /v1/shared/items/{id}/rotate/candidate` | Read the candidate while rotating | `read_candidate` |
| `POST /v1/shared/items/{id}/rotate/recover` | Read the candidate of a stale rotation | `recover` |
| `POST /v1/shared/items/{id}/rotate/commit` | Promote the candidate | `rotate_commit` |
| `POST /v1/shared/items/{id}/rotate/abort` | Discard the candidate | `rotate_abort` |

Vault `admin` and `operator` roles may perform all of these; `member` and
`readonly` may not.

`abort` accepts `{"reason": "…", "force": false}`. The reason is recorded and
returned by `rotate/status`, which is what a later operator sees when asking why
a rotation stopped. A normal abort accepts only the known `rotating` and `stale`
states. `force: true` is checked as a separate `rotate_abort_force` action and
is available to vault admins only — it exists to clear an unknown or corrupted
rotation state. Both forms use compare-and-swap and refuse to clear a rotation
that changed concurrently.

### Timing

Configured under `rotation:` in the server config:

| Setting | Default | Meaning |
|---|---|---|
| `lock_ttl_seconds` | `600` | How long a rotation may stay open before turning stale |
| `stale_retention_seconds` | `86400` | How long a stale candidate remains recoverable |
| `cleanup_interval_seconds` | `600` | Background sweep interval |
| `max_versions` | `5` | Retained historical versions per item |

### A rotation from the outside

The native CLI wraps the same state machine without putting either value in
argv or the environment:

```bash
zann rotate services/web/database --vault infra --policy database \
  --exec /usr/local/libexec/rotate-web-database \
  --exec-arg production
```

Zann starts the rotation and writes exactly one JSON document to the hook's
stdin:

```json
{"previous":"…","candidate":"…"}
```

The start response carries `previous_version`; Zann requires it to match the
version it just read and aborts before launching the hook if the item changed
in between.

`--exec` launches an executable directly, not through a shell. Repeat
`--exec-arg` for non-secret arguments. Hook stdout and stderr remain attached
to the operator's terminal but are never copied into Zann audit events. Zann
credential variables (`ZANN_SERVICE_TOKEN`, `ZANN_ACCESS_TOKEN`, `ZANN_TOKEN`,
and `ZANN_TOKEN_FILE`) are removed from the inherited hook environment. The
default hook timeout is 300 seconds and is capped at 15 seconds before the
server's `expires_at`, leaving time for commit.

A spawn error, stdin error, non-zero exit, signal, or timeout terminates the
hook and aborts the rotation. On Unix, Zann terminates the hook's whole process
group before aborting. If the hook succeeds but commit fails, Zann does **not**
abort: the external system may already use the candidate, so the rotation is
left available through status/candidate or stale recovery.

The hook needs both `read` (to obtain the previous value) and the explicit
`rotate` scope. `write` alone never grants coordinated rotation. Force-abort
remains admin-only.

The equivalent manual HTTP flow is:

```bash
ITEM=https://zann.example.com/v1/shared/items/$ITEM_ID
AUTH="Authorization: Bearer $ACCESS_TOKEN"

# 1. take the lock and read the candidate
CANDIDATE=$(curl -sS -X POST -H "$AUTH" -H 'content-type: application/json' \
  "$ITEM/rotate/start" -d '{"policy":"database"}' | jq -r .candidate)

# 2. apply it to the external system
if psql "$ADMIN_DSN" -c "ALTER USER webapp PASSWORD '$CANDIDATE'"; then
  curl -sS -X POST -H "$AUTH" "$ITEM/rotate/commit"
else
  curl -sS -X POST -H "$AUTH" -H 'content-type: application/json' \
    "$ITEM/rotate/abort" -d '{"reason":"database rejected the candidate"}'
fi
```

The ordering matters: apply externally **before** committing. If the external
step fails, aborting leaves consumers using a value that still works. If the
process dies between the two steps, `rotate/status` reports `stale` and
`rotate/recover` returns the same candidate so the operation can be finished
rather than guessed at.

### Rotation error codes

| `error` | Meaning |
|---|---|
| `rotation_in_progress` | A rotation is already open on this item |
| `rotation_not_active` | No rotation is open |
| `rotation_active` | `recover` was called while the lock is still valid — use `candidate` |
| `rotation_expired` | The stale retention window has passed |
| `rotation_invalid_state` | Normal abort found an unknown rotation state; an admin may use force-abort |
| `rotation_conflict` | The rotation changed while abort was in progress; inspect status and retry deliberately |
| `invalid_abort_reason` | Abort reason is empty, contains control characters, or exceeds 1024 bytes |
| `password_field_missing` | The item has no `value`/password field to rotate |
| `password_field_ambiguous` | The item has several password fields but none is named `password` |
| `invalid_policy` | The requested generation policy is unknown |
| `version_conflict`, `history_conflict` | The item changed underneath the rotation; restart it |

### Version history

```bash
curl -sS -H "$AUTH" "$ITEM/history"
curl -sS -H "$AUTH" "$ITEM/history/4"
```

Listing requires `read_history`; reading one version requires `read_previous`.
The five most recent versions are retained (`rotation.max_versions`); this is a
rollback and hand-over aid, not a general version store.

## Observability

Every read, write, ensure and rotation emits a structured audit line with
`event=audit`, `category=secrets`, the action, the outcome, the vault, the item
path and the acting identity — user, device and service account. **Values are
never logged**, and neither are hashes derived from them.

Prometheus metrics:

- `zann_secrets_operations_total{operation,result}`
- `zann_secrets_operation_duration_seconds{operation,result}`
- `zann_forbidden_access_total{resource}` (the resource label is redacted under
  the production metrics profile)

Alert on a rising `forbidden` result: for a machine whose scopes were correct
yesterday, it usually means an expired token or a moved path, and the workload
is about to fail.

## Current limitations

These are known and intentional to record rather than imply away:

- **Item granularity.** A scope grants every field of a matching item; there is
  no field-level authorization.
- **The CLI surface is partial.** `zann secret list`, `get`, `set`, `ensure`,
  the single-shot `rotate`, coordinated top-level `zann rotate`, and
  batch-backed `materialize` use this API. There is no direct `batch/ensure`
  command; see the [CLI Guide](CLI.md).
- **Revocation does not reach running processes.** A process that already holds
  a value keeps it until it restarts or explicitly re-reads a trusted source.
  The NixOS/systemd adapter always restarts because reload does not recreate
  systemd credentials.
- **Zann has not passed a security audit** and is not recommended for
  production. That applies with particular force to this plane, where a defect
  affects service credentials rather than a single stored password.
