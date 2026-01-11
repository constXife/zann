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

Get the server info (includes fingerprint):

```bash
zann server info https://zann.company.com
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

## Load testing (k6)

Local/dev only. Example test user:
- email: `loadtest.admin@local.test`
- password: `Loadtest123!`

Highload env overrides:
- Copy `.env.highload.example` to `.env.highload` (used by `compose.loadtest.yaml`).
- Copy `compose.loadtest.example.yaml` to `compose.loadtest.yaml` for local/infra-specific overrides.
- If your OTLP endpoint uses a private CA, mount the CA in `compose.loadtest.yaml` and set `ZANN_TRACING_OTEL_CA_FILE`.

Reset and provision the loadtest database (drops the loadtest volume by default).
This uses a dedicated compose project name (`zann_loadtest`) so it won't affect the main stack:

```bash
./loadtest/reset_db.sh
```

Full reset (stop everything and drop volumes) for the loadtest stack:

```bash
podman compose -p zann_loadtest -f compose.yaml -f compose.loadtest.yaml down -v
```

Skip the reset step if you only want to re-provision:

```bash
ZANN_LOADTEST_RESET_DB=0 ./loadtest/reset_db.sh
```

Create user (once) and fetch an access token:

```bash
curl -s http://localhost:18080/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"loadtest.admin@local.test","password":"Loadtest123!","device_name":"k6"}' \
  | jq -r .access_token
```

If the user already exists, login instead:

```bash
curl -s http://localhost:18080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"loadtest.admin@local.test","password":"Loadtest123!","device_name":"k6"}' \
  | jq -r .access_token
```

Run k6:

```bash
ZANN_BASE_URL=http://localhost:18080 \
ZANN_ACCESS_TOKEN=$(curl -s http://localhost:18080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"loadtest.admin@local.test","password":"Loadtest123!","device_name":"k6"}' \
  | jq -r .access_token) \
k6 run loadtest/k6/zann_smoke.js
```

Morning sync (500 VUs by default, configurable):

```bash
ZANN_SERVICE_ACCOUNT_TOKEN="$(cat ./loadtest/data/loadtest_sa_token)" \
ZANN_BASE_URL=http://localhost:18080 \
ZANN_PEAK_VUS=500 \
ZANN_HOLD_DURATION=5m \
k6 run loadtest/k6/zann_morning_sync.js
```

Loadtest env shortcut (optional):

```bash
cp loadtest/.env.k6.example loadtest/.env.k6
```

Then run morning sync with reset + metrics:

```bash
./loadtest/run_morning.sh
```

Morning sync with resource watchdog (VictoriaMetrics instant queries):

```bash
ZANN_SERVICE_ACCOUNT_TOKEN="$(cat ./loadtest/data/loadtest_sa_token)" \
ZANN_BASE_URL=http://localhost:18080 \
ZANN_PEAK_VUS=500 \
ZANN_HOLD_DURATION=5m \
VM_URL=https://vm.arkham.void \
CPU_QUERY='avg(rate(process_cpu_seconds_total{env="loadtest"}[1m]))' \
MEM_QUERY='max(process_resident_memory_bytes{env="loadtest"})' \
ZANN_MEM_LIMIT_BYTES=1000000000 \
ZANN_CPU_LIMIT=0.85 \
k6 run \
  --tag job=k6 \
  --tag env=loadtest \
  --tag instance=desktop \
  --tag test=zann_morning_sync \
  loadtest/k6/zann_morning_sync.js
```

Low-load sanity (CPU/mem guardrails; good for regression checks):

```bash
ZANN_SERVICE_ACCOUNT_TOKEN="$(cat ./loadtest/data/loadtest_sa_token)" \
ZANN_BASE_URL=http://localhost:18080 \
VM_URL=https://vm.arkham.void \
CPU_QUERY='avg(rate(process_cpu_seconds_total{env="loadtest"}[1m]))' \
MEM_QUERY='max(process_resident_memory_bytes{env="loadtest"})' \
ZANN_MEM_LIMIT_BYTES=500000000 \
ZANN_CPU_LIMIT=0.3 \
k6 run \
  --tag job=k6 \
  --tag env=loadtest \
  --tag instance=desktop \
  --tag test=zann_sanity_lowload \
  loadtest/k6/zann_sanity_lowload.js
```

Morning sync with remote_write metrics:

```bash
ZANN_SERVICE_ACCOUNT_TOKEN="$(cat ./loadtest/data/loadtest_sa_token)" \
ZANN_BASE_URL=http://localhost:18080 \
ZANN_PEAK_VUS=500 \
ZANN_HOLD_DURATION=5m \
K6_PROMETHEUS_RW_SERVER_URL=https://vm.arkham.void/api/v1/write \
K6_PROMETHEUS_RW_PUSH_INTERVAL=1s \
k6 run -o experimental-prometheus-rw \
  --tag job=k6 \
  --tag env=loadtest \
  --tag instance=desktop \
  --tag test=zann_morning_sync \
  loadtest/k6/zann_morning_sync.js
```

Custom stages (JSON array):

```bash
ZANN_SERVICE_ACCOUNT_TOKEN="$(cat ./loadtest/data/loadtest_sa_token)" \
ZANN_BASE_URL=http://localhost:18080 \
K6_STAGES='[{"duration":"1m","target":200},{"duration":"3m","target":500},{"duration":"1m","target":0}]' \
k6 run loadtest/k6/zann_morning_sync.js
```

Send k6 metrics to VictoriaMetrics (remote_write):

```bash
ZANN_BASE_URL=http://localhost:18080 \
ZANN_ACCESS_TOKEN=$(curl -s http://localhost:18080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"loadtest.admin@local.test","password":"Loadtest123!","device_name":"k6"}' \
  | jq -r .access_token) \
K6_PROMETHEUS_RW_SERVER_URL=https://vm.arkham.void/api/v1/write \
K6_PROMETHEUS_RW_PUSH_INTERVAL=1s \
k6 run -o experimental-prometheus-rw \
  --tag job=k6 \
  --tag env=loadtest \
  --tag instance=desktop \
  --tag test=zann_smoke \
  loadtest/k6/zann_smoke.js
```

E2E tests can reuse the same user/token approach; just keep a dedicated account and clean test data.

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
