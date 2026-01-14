set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    just server-lint
    just server-test

db_url := "sqlite://./.tmp/dev.db"
pg_url := "postgres://zann:zann@127.0.0.1:5432/zann"
pg_test_url := "postgres://zann:zann@127.0.0.1:5433/zann"

MIGRATE_SOURCE := "--source crates/zann-server/migrations"

fmt:
    cargo fmt --check

clippy:
    cargo clippy --all-targets -- -D warnings

audit:
    cargo audit

check: fmt clippy
    cargo test

fast-test:
    cargo test

# ==========================================
# E2E
# ==========================================

e2e: e2e-desktop e2e-cli

e2e-desktop:
    just desktop-e2e

e2e-cli:
    cargo test -p zann-cli --test e2e -- --nocapture

desktop-test:
    cd apps/desktop && bun run test

desktop-build:
    cd apps/desktop && bun run tauri build

desktop-e2e +args='':
    @echo "E2E is temporarily disabled."

db-up:
    podman compose up -d db

db-down:
    podman compose down

db-reset:
    podman compose down -v

server-test-db:
    podman compose -p zann_test -f compose.test.yaml up -d db
    bash -euo pipefail -c 'set +e; TEST_DATABASE_URL={{pg_test_url}} RUST_TEST_THREADS=1 cargo test -p zann-server --features postgres-tests -- --test-threads=1; status=$?; set -e; podman compose -p zann_test -f compose.test.yaml down; exit $status'

test-db-down:
    podman compose -p zann_test -f compose.test.yaml down

server-migrate:
    mkdir -p .tmp
    DATABASE_URL={{db_url}} sqlx database create
    DATABASE_URL={{db_url}} sqlx migrate run {{MIGRATE_SOURCE}}

server-lint:
    just server-migrate
    DATABASE_URL={{db_url}} cargo fmt --check
    DATABASE_URL={{db_url}} cargo clippy -- -D warnings

server-test:
    just server-test-db

server-run:
    just server-migrate
    DATABASE_URL={{db_url}} cargo run -p zann-server

server-run-dev:
    just server-migrate
    ZANN_PASSWORD_PEPPER=dev-pepper \
    ZANN_TOKEN_PEPPER=dev-pepper \
    DATABASE_URL={{db_url}} \
    cargo run -p zann-server

cli-build:
    cargo build -p zann-cli --release

cli-test:
    cargo test -p zann-cli

lint:
    just server-lint

test:
    just fast-test

full-test:
    just fast-test
    just server-test-db
    just desktop-test
    just desktop-build

run:
    just server-run

run-dev:
    just server-run-dev

cli:
    just cli-build

# ==========================================
# Loadtest (k6)
# ==========================================

k6 scenario='baseline_normal' +args='':
    K6_SCENARIO={{scenario}} ./loadtest/run_scenario.sh {{args}} run loadtest/k6/runner.js

k6-scenario +args='':
    ./loadtest/run_scenario.sh {{args}} run loadtest/k6/runner.js
