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

# COSMIC PoC (apps/cosmic): needs the `cosmic` dev shell, see apps/cosmic/README.md
cosmic-run +args='':
    cd apps/cosmic && cargo run {{args}}

cosmic-build:
    cd apps/cosmic && cargo build --release

cosmic-test:
    cd apps/cosmic && cargo test

# Install into ~/.local so the COSMIC launcher can start it like any other app
cosmic-install:
    #!/usr/bin/env bash
    set -euo pipefail
    cd apps/cosmic && cargo build --release && cd ../..
    install -Dm755 apps/cosmic/target/release/zann-cosmic "$HOME/.local/libexec/zann-cosmic"
    # winit dlopens libwayland at startup, so a bare Exec= from the launcher
    # dies with NoWaylandLib on NixOS, where nothing is in a global lib dir.
    # Bake in the library path of the shell that built it.
    {
      echo '#!/usr/bin/env bash'
      if [ -n "${LD_LIBRARY_PATH:-}" ]; then
        echo "export LD_LIBRARY_PATH=\"$LD_LIBRARY_PATH\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\""
      fi
      echo 'exec "$HOME/.local/libexec/zann-cosmic" "$@"'
    } > "$HOME/.local/bin/zann-cosmic"
    chmod 755 "$HOME/.local/bin/zann-cosmic"
    # One logo for the whole product, so the icons come from the Tauri app
    # rather than a second copy of the same PNGs.
    for pair in 32:32x32 64:64x64 128:128x128 256:128x128@2x 512:icon; do
      size="${pair%%:*}"; src="${pair##*:}"
      install -Dm644 "apps/desktop/src-tauri/icons/${src}.png" \
        "$HOME/.local/share/icons/hicolor/${size}x${size}/apps/com.rlyeh.zann.Cosmic.png"
    done
    install -d "$HOME/.local/share/applications"
    sed "s|^Exec=zann-cosmic$|Exec=$HOME/.local/bin/zann-cosmic|" \
      apps/cosmic/data/com.rlyeh.zann.Cosmic.desktop \
      > "$HOME/.local/share/applications/com.rlyeh.zann.Cosmic.desktop"
    command -v update-desktop-database >/dev/null && \
      update-desktop-database "$HOME/.local/share/applications" || true
    command -v gtk-update-icon-cache >/dev/null && \
      gtk-update-icon-cache -qtf "$HOME/.local/share/icons/hicolor" || true
    echo "installed: $HOME/.local/bin/zann-cosmic"

cosmic-uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f "$HOME/.local/bin/zann-cosmic" "$HOME/.local/libexec/zann-cosmic"
    rm -f "$HOME/.local/share/applications/com.rlyeh.zann.Cosmic.desktop"
    for size in 32 64 128 256 512; do
      rm -f "$HOME/.local/share/icons/hicolor/${size}x${size}/apps/com.rlyeh.zann.Cosmic.png"
    done
    command -v update-desktop-database >/dev/null && \
      update-desktop-database "$HOME/.local/share/applications" || true
    echo "removed"

db-up:
    podman compose up -d db

db-down:
    podman compose down

db-reset:
    podman compose down -v

server-test-db:
    podman compose -p zann_test -f compose.test.yaml up -d db
    bash -euo pipefail -c 'set +e; TEST_DATABASE_URL={{pg_test_url}} RUST_TEST_THREADS=1 cargo test -p zann-server --features postgres-tests -- --test-threads=1; status=$?; set -e; podman compose -p zann_test -f compose.test.yaml down; exit $status'

server-create-db-pg db:
    DATABASE_URL={{db}} cargo run -p zann-db --features postgres --bin create_database

server-migrate-pg db:
    just server-create-db-pg {{db}}
    ZANN_CONFIG_PATH=config/ci.yaml ZANN_DB_URL={{db}} cargo run -p zann-server --bin zann-server -- migrate

server-test-pg db:
    just server-migrate-pg {{db}}
    ZANN_CONFIG_PATH=config/ci.yaml ZANN_DB_URL={{db}} TEST_DATABASE_URL={{db}} RUST_TEST_THREADS=1 cargo test -p zann-server --features postgres-tests -- --test-threads=1

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
