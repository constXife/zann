#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "${script_dir}/.env.k6" ]; then
  set -a
  # shellcheck source=/dev/null
  . "${script_dir}/.env.k6"
  set +a
fi

export ZANN_BASE_URL="${ZANN_BASE_URL:-http://localhost:18080}"

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <k6-args...>"
  echo "Example: K6_SCENARIO=baseline_normal K6_PROFILE=normal $0 run loadtest/k6/runner.js"
  exit 1
fi

exec k6 "$@"
