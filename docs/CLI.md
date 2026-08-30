---
title: CLI Guide
description: Token-based CLI usage for automation and shared vault access.
---

## Overview

The Zann CLI is token-based and intended for automation and CI/CD workflows.
Tokens are issued and managed by the server (service account tokens).

## Getting a token

Create a service account token on the server:

```bash
zann-server token create ci-prod infra:/
```

The arguments are `<name> <vault:prefixes> [ops]`: `/` grants the whole vault,
a comma-separated list grants subtrees, and `ops` defaults to `read`. Scope a
token to what the job actually needs:

```bash
zann-server token create deployer infra:services/web read,write --ttl 30d
zann-server token create db-rotator infra:services/web read,rotate --ttl 30d
```

Store the token securely (CI secret store or vault). When provisioning a host,
write it straight to a file instead of through a terminal:

```bash
zann-server provision ensure-token yogg-grafana \
  infra:rlyeh/yogg/grafana read \
  --write-token-file /run/secrets/yogg-zann-token
```

## Authentication model

- **Service account token**: long-lived token issued by the server (`zann_sa_...`).
- **Access token**: short-lived token exchanged by the CLI when needed.

The CLI will exchange a service account token for an access token automatically.

## Supplying tokens

Provide a token in one of these ways:

- `--token-file`
- `ZANN_TOKEN_FILE` environment variable
- `ZANN_SERVICE_TOKEN` environment variable
- a context populated with `zann config set-context ... --token-file ...`

Prefer a private token file. The CLI intentionally does not accept token values
as command-line arguments because command lines may be readable through `ps`.

## Basic usage

```bash
TOKEN_FILE=/run/secrets/zann-service-account-token

# Verify connectivity and identity
zann --addr https://zann.example.com --token-file "$TOKEN_FILE" whoami

# List shared items
zann --addr https://zann.example.com --token-file "$TOKEN_FILE" list --vault infra --format json

# Fetch a single item
zann --addr https://zann.example.com --token-file "$TOKEN_FILE" get infra/db/creds password
```

## Configuring contexts

Store server and token information in a local context:

```bash
zann config set-context ci \
  --addr https://zann.example.com \
  --token-file /run/secrets/zann-service-account-token \
  --vault infra
```

Then use the context without repeating flags:

```bash
zann --context ci list --format json
```

## Output formats

- `list --format table|json`
- `get --format json|kv|env`

Examples:

```bash
zann get infra/db/creds --format env
zann list --vault infra --format json
```

## Templates and materialization

Render templates with secrets:

```bash
zann render --vault infra --template template.txt --out app.env
```

Materialize secrets to files:

```bash
zann materialize --vault infra --out ./secrets --field value
```

`materialize` is a machine-secrets command: `--field` is required and its only
accepted value is `value`. It never projects an arbitrary item payload. The CLI
uses the metadata-only secrets list to discover matching paths, then reads
secret values through `secrets/batch/get` in chunks of at most 64 instead of
issuing one payload request per item.

Each batch chunk is fail-closed: if any entry reports an error, no file from
that chunk is written. Files from earlier successful chunks may already have
been published, so a multi-chunk materialization is not globally atomic.

Materialization rejects traversal and symlinks inside the output tree, bounds
each output to 256 KiB, creates output directories and files as `0700`/`0600`
on Unix, and publishes through an atomic same-directory replacement. The
staging file and directory entry are synced before success is reported. An
existing output root must already have mode `0700`; the CLI refuses a broader
directory instead of silently changing its permissions.

For a service with several related credentials, use a versioned delivery
profile instead of observing independently replaced files:

```yaml
# web-secrets.yaml — references only, never values
version: 1
vault: infra
files:
  - secret: services/web/database
    target: database-password
  - secret: services/web/session-key
    target: session-key
```

```bash
zann delivery apply --profile web-secrets.yaml --out /run/zann/web
```

The command resolves all references in one bounded batch and prints only the
new generation UUID. It writes values below
`/run/zann/web/generations/<uuid>/`, then atomically replaces the private,
regular `/run/zann/web/current` file with that UUID. A consumer reads `current`
once and uses that fixed generation for every credential. The previous
generation is retained by default; use `--retain-generations 1` to keep only
the current one.

Profiles accept 1–64 exact paths from one vault. They reject unknown fields,
selectors, duplicate sources or targets, absolute targets, traversal and
hidden target segments. Applying a profile never provisions a missing secret,
falls back to stale data, restarts a service, or writes values to stdout.

`--max-total-bytes N` lets an adapter impose a smaller aggregate sink limit
before any generation is published. `--skip-unchanged` securely compares the
exact current target set and values and reuses its UUID when nothing changed;
it stores no value-derived hash. The NixOS/systemd adapter uses both options and
is documented in [NixOS Secret Delivery](NixOS-Delivery.md).

## Running commands with secrets

`zann run` injects the fields of one item as environment variables for a
subprocess:

```bash
zann run --vault infra app/db/creds -- sh -c 'echo "$password"'
```

It requires a service account token, resolves exactly one item, and skips
fields whose names are not valid shell identifiers with a warning on stderr.

Environment variables are inherited by every child of the command and can be
exposed by process-inspection interfaces. For long-running services, prefer a
file-based credential mechanism — on systemd, `LoadCredential=` reading a file
materialized outside the unit — over a process-wide environment.

## Machine secrets

The server also exposes a machine-facing secrets API with idempotent
provisioning (`ensure`), batch reads, generation policies and coordinated
two-phase rotation. The first native CLI commands read a value and provision a
generated value if it is absent:

```bash
zann secret get services/web/database --vault infra
zann secret list --vault infra --prefix services/web --format json
zann secret ensure services/web/session-key --vault infra --policy strong
zann secret set services/web/database --vault infra \
  --value-file /run/secrets/new-database-password
zann secret rotate services/web/session-key --vault infra --policy strong
zann secret get services/web/database --vault infra --previous
```

The four value-producing commands print only the resulting secret value by
default, without adding a trailing newline. Use `--format json` when item ID,
path, policy, metadata, version and `created` state are needed. `ensure` preserves an
existing value and fails on a policy mismatch; it never silently regenerates
it.

`secret list` returns metadata only: `path`, `version`, and `updated_at`. It
never reads or prints secret values. Pages contain 50 entries by default and at
most 100; pass the opaque `next_cursor` back through `--cursor`. A
prefix-scoped service account must pass a prefix covered by its scope.

`secret set` never accepts the value as an argument. Pass exactly one of
`--value-file FILE` or `--stdin`. Input must be UTF-8 and at most 256 KiB;
whitespace, including a final newline, is preserved exactly. A value-file must
resolve to a regular file.

`secret rotate` is the single-shot operation: it immediately replaces the
stored value and reports `previous_version` in JSON output. It does not update
an external database or service. Use coordinated rotation when the consumer
must be changed before commit.

For an external database or provider, use the coordinated top-level command:

```bash
zann rotate services/web/database --vault infra --policy database \
  --exec /usr/local/libexec/rotate-web-database \
  --exec-arg production
```

The executable is launched directly without a shell. It receives exactly one
JSON document on stdin with `previous` and `candidate` fields; neither value is
placed in argv or the environment. Repeat `--exec-arg` for non-secret
arguments. Zann credential environment variables are removed before launch. A
non-zero exit, signal, stdin failure, or timeout aborts the
rotation. A successful hook is followed by commit. If commit itself fails, the
rotation is deliberately left recoverable because the external effect may
already have happened.

The hook timeout defaults to 300 seconds, is configurable through
`--timeout-seconds`, and is capped before the server lease expires. Hook stdout
and stderr are forwarded to the terminal, so the hook itself must not print
credentials. Service accounts require both `read` and the explicit `rotate`
scope; `write` is insufficient. Force-abort remains admin-only.

`secret get --previous` requests only the immediately previous version during
the server grace window and requires `read_previous`. It never silently falls
back when the current version is unavailable.

There is no direct CLI surface for `batch/ensure`; use the HTTP API documented
in the [Machine Secrets guide](Machine-Secrets.md).

## Security notes

- Prefer HTTPS. `--insecure` disables TLS checks and allows http.
- You can pin fingerprints with `ZANN_SERVER_FINGERPRINT`.
- Tokens should be scoped and rotated on the server.
- Pass tokens by file, not on the command line.
- Only shared, server-encrypted vaults are reachable with a service account
  token. Personal vaults are client-encrypted and cannot be read by automation.

## Troubleshooting

- `token is required`: provide `--token-file`, `ZANN_SERVICE_TOKEN`, or set a context.
- `refusing to use http://`: add `--insecure` for local testing.
- Use `-v` or `-vv` for more logs.
