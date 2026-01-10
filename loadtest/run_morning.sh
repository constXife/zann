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

"${script_dir}/reset_db.sh"

export ZANN_SERVICE_ACCOUNT_TOKEN="$(cat "${script_dir}/data/loadtest_sa_token")"

if [ -z "${ZANN_TEST_RUN_ID:-}" ]; then
  ZANN_TEST_RUN_ID="k6-$(date +%s)-${RANDOM}"
fi
export ZANN_TEST_RUN_ID
if [ -z "${K6_TAG_TEST:-}" ]; then
  K6_TAG_TEST="${ZANN_TEST_RUN_ID}"
fi
export K6_TAG_TEST

k6_tags=()
if [ -n "${K6_TAG_JOB:-}" ]; then
  k6_tags+=("--tag" "job=${K6_TAG_JOB}")
fi
if [ -n "${K6_TAG_ENV:-}" ]; then
  k6_tags+=("--tag" "env=${K6_TAG_ENV}")
fi
if [ -n "${K6_TAG_INSTANCE:-}" ]; then
  k6_tags+=("--tag" "instance=${K6_TAG_INSTANCE}")
fi
if [ -n "${K6_TAG_TEST:-}" ]; then
  k6_tags+=("--tag" "test=${K6_TAG_TEST}")
fi

K6_SCENARIO="${K6_SCENARIO:-morning_sync}" \
  "${script_dir}/run_scenario.sh" -o experimental-prometheus-rw "${k6_tags[@]}" run loadtest/k6/runner.js
