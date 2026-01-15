# zann-server

Zann server provides the API, shared vaults, and token issuance for CLI access.

## Overview

- HTTP API for clients (desktop and CLI)
- Shared vault encryption and access control
- Service account tokens for automation

## Running locally (Docker Compose)

```bash
git clone https://github.com/constXife/zann
cd zann
docker compose up -d
```

## Prebuilt image

```bash
docker pull constxife/zann-server:latest
```

## Configuration

Start from `config/config.example.yaml` and supply required secrets via env:

- `ZANN_PASSWORD_PEPPER`
- `ZANN_TOKEN_PEPPER`
- `ZANN_SMK_FILE` or `server.master_key`
- `ZANN_CONFIG_PATH`

## Environment variables

Common env vars:

- `ZANN_CONFIG_PATH` - path to the server config file
- `ZANN_ENV` - environment name (`prod` enables stricter output in health checks)
- `ZANN_PASSWORD_PEPPER` / `ZANN_PASSWORD_PEPPER_FILE`
- `ZANN_TOKEN_PEPPER` / `ZANN_TOKEN_PEPPER_FILE`
- `ZANN_SMK` / `ZANN_SMK_FILE`

## Migrations

Run database migrations via the server CLI:

```bash
zann-server migrate
```

## Tokens (service accounts)

Create and manage tokens for CLI automation:

```bash
zann-server token create ci-prod infra:/
zann-server token list
zann-server token revoke <token_id>
```

## Health endpoint

The server exposes a health check at:

```
GET /health
```

It includes component status (`db`, `db_pool`, `kdf`, `oidc`) and version info.

## Security notes

- Prefer HTTPS and pin the server fingerprint in clients.
- Keep token scopes narrow and rotate regularly.
