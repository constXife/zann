# Zann

Self-hosted password manager for individuals and small teams.

Important:
- Not recommended for production use.
- The codebase was written by an LLM and has not undergone a security audit.
- The project is under active development; breaking changes are possible.

## Clients

- Desktop: Tauri (macOS, Windows)
- Linux: CLI

## Quick start

Docker Compose:

```bash
docker compose up --build
```

## Config

- `ZANN_CONFIG_PATH` defaults to `config.yaml` in repo root
- Example config: `config/config.example.yaml`
- OIDC: use `jwks_url` for auto-fetch or `jwks_file` for offline/local JWKS
- Blob format: V1 envelope (magic `ZAN`, version `1`)
- Server master key: set `ZANN_SMK_FILE` to auto-generate on first start
- Self-hosting: mount `/config` and `/data`, and persist the SMK file

Required env for `zann-server`:
- `ZANN_SMK` or `ZANN_SMK_FILE` (server master key for shared vault encryption)
- `ZANN_TOKEN_PEPPER` or `ZANN_TOKEN_PEPPER_FILE` (pepper for token hashing and server fingerprint)
- `ZANN_PASSWORD_PEPPER` or `ZANN_PASSWORD_PEPPER_FILE` (required when internal auth is enabled)

Notes:
- If `ZANN_TOKEN_PEPPER` is unset, it defaults to `ZANN_PASSWORD_PEPPER`.

## Security model

- Secrets are encrypted at rest in the DB; clients decrypt locally using vault keys
- Personal vaults: client-side encryption only
- Shared vaults: server-side encryption for team workflows
- Server sees metadata; only shared vault contents are readable server-side
- File secrets (MVP): stored as attachments in server DB. `personal` uses opaque ciphertext only; `shared` supports `plain` or `opaque` representations.

Threat model for server: `crates/zann-server/SECURITY.md`

## CLI + server basics

Service account token (CI/CD):

```bash
zann-server tokens create --name "Jenkins Prod" \
  --vault infra-prod \
  --prefix payments/gateway/prod/ \
  --ops read \
  --ttl 365d \
  --issued-by-email admin@example.com
```

Use from CI:

```bash
export ZANN_SERVER_URL=https://zann.company.com
export ZANN_SERVICE_TOKEN=zann_sa_XXXXXXXXXXXXXXXXXXXXXXXX
export ZANN_SERVER_FINGERPRINT=sha256:abc123...

zann get db/postgres password
```

Get the server fingerprint:

```bash
zann server fingerprint https://zann.company.com
```

Notes:
- Pinning means the CLI trusts only the expected fingerprint
- `#field` is optional (defaults to `password`)
- Secrets override existing env vars with the same name
- File secrets are not yet supported in the CLI; use the API (`POST/GET /v1/vaults/:vault_id/items/:item_id/file` with `representation=plain|opaque`).
- Default server `max_body_bytes` is 16MB; adjust if you need larger file uploads.

File upload/download API (shared vault example):

Notes:
- Shared uploads require `payload.extra.file_id` and `payload.extra.upload_state=pending` on the item; otherwise the upload returns `upload_state_invalid`, `file_id_missing`, or `file_id_mismatch`.

```bash
curl -X POST \
  "https://zann.company.com/v1/vaults/$VAULT_ID/items/$ITEM_ID/file?representation=plain&file_id=$FILE_ID" \
  -H "Authorization: Bearer $ZANN_SERVICE_TOKEN" \
  -H "Content-Type: application/pdf" \
  --data-binary @document.pdf

curl -X GET \
  "https://zann.company.com/v1/vaults/$VAULT_ID/items/$ITEM_ID/file?representation=plain" \
  -H "Authorization: Bearer $ZANN_SERVICE_TOKEN" \
  -o document.pdf
```


## Operations

Docker build:
- `crates/zann-server/Dockerfile` uses `cargo-chef` for faster rebuilds

Migrations:
- `crates/zann-server/migrations/` — server DB (Postgres)
- `crates/zann-db/migrations/` — client local DB (SQLite)

Run server migrations:

```bash
ZANN_DB_URL=postgres://zann:zann@127.0.0.1:5432/zann zann-server migrate
```

SQLx CLI (dev):

```bash
cargo install sqlx-cli --no-default-features --features postgres
```

## Observability

- Sentry: set `sentry.enabled` and `sentry.dsn` in config
- Metrics: set `metrics.enabled` and expose `metrics.endpoint` (Prometheus/VictoriaMetrics)

## Dev workflow

Tests:

```bash
export TEST_DATABASE_URL=postgres://zann:zann@127.0.0.1:5432/zann
cargo test
```

Lint:

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

Security audit:

```bash
cargo install cargo-audit
cargo audit
```

Task runner (just):

```bash
just migrate
just lint
just test
just audit
just run
```

## Docs

- `ROADMAP.md`
- `CONTRIBUTING.md`
