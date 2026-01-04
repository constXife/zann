#!/usr/bin/env bash
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  echo "podman not found"
  exit 1
fi

if ! command -v podman-compose >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
  echo "podman-compose or docker-compose not found"
  exit 1
fi

podman compose up -d db

export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgres://zann:zann@127.0.0.1:5432/zann}"

cargo test -p zann-server --test client_workflow
