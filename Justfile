set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    just server-lint
    just server-test

db_url := "sqlite://./.tmp/dev.db"
pg_url := "postgres://zann:zann@127.0.0.1:5432/zann"

MIGRATE_SOURCE := "--source crates/zann-server/migrations"

fmt:
    cargo fmt --check

clippy:
    cargo clippy --all-targets -- -D warnings

audit:
    cargo audit

check: fmt clippy
    cargo test

db-up:
    podman compose up -d db

db-down:
    podman compose down

db-reset:
    podman compose down -v

server-test-db:
    just db-up
    TEST_DATABASE_URL={{pg_url}} cargo test -p zann-server --features postgres-tests

server-migrate:
    mkdir -p .tmp
    DATABASE_URL={{db_url}} sqlx database create
    DATABASE_URL={{db_url}} sqlx migrate run {{MIGRATE_SOURCE}}

server-lint:
    just server-migrate
    DATABASE_URL={{db_url}} cargo fmt --check
    DATABASE_URL={{db_url}} cargo clippy -- -D warnings

server-test:
    just server-migrate
    DATABASE_URL={{db_url}} cargo test -p zann-server

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
    just server-test

run:
    just server-run

run-dev:
    just server-run-dev

cli:
    just cli-build
