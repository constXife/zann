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

Store the token securely (CI secret store or vault).

## Authentication model

- **Service account token**: long-lived token issued by the server (`zann_sa_...`).
- **Access token**: short-lived token exchanged by the CLI when needed.

The CLI will exchange a service account token for an access token automatically.

## Supplying tokens

Provide a token in one of these ways:

- `--token`
- `--token-file`
- `ZANN_TOKEN` environment variable
- `zann config set-context ... --token ...`

## Basic usage

```bash
# Verify connectivity and identity
zann --addr https://zann.example.com --token "$TOKEN" whoami

# List shared items
zann --addr https://zann.example.com --token "$TOKEN" list --vault infra --format json

# Fetch a single item
zann --addr https://zann.example.com --token "$TOKEN" get infra/db/creds password
```

## Configuring contexts

Store server and token information in a local context:

```bash
zann config set-context ci \
  --addr https://zann.example.com \
  --token "$TOKEN" \
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
zann materialize --vault infra --out ./secrets --field password
```

## Running commands with secrets

`zann run` injects secrets as environment variables for a subprocess:

```bash
zann run --vault infra app/db/creds -- sh -c 'echo "$password"'
```

## Security notes

- Prefer HTTPS. `--insecure` disables TLS checks and allows http.
- You can pin fingerprints with `ZANN_SERVER_FINGERPRINT`.
- Tokens should be scoped and rotated on the server.

## Troubleshooting

- `token is required`: provide `--token`, `--token-file`, or set a context.
- `refusing to use http://`: add `--insecure` for local testing.
- Use `-v` or `-vv` for more logs.
