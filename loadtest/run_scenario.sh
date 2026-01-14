#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

heap_dir="${ZANN_HEAP_PROFILE_DIR:-${script_dir}/data/heap}"
heap_clean="${ZANN_HEAP_PROFILE_CLEAN:-1}"
heap_sleep_seconds="${ZANN_HEAP_PROFILE_SLEEP:-60}"

if [ -f "${script_dir}/.env.k6" ]; then
  set -a
  # shellcheck source=/dev/null
  . "${script_dir}/.env.k6"
  set +a
fi

export ZANN_BASE_URL="${ZANN_BASE_URL:-http://localhost:18080}"
export K6_PROFILE="${K6_PROFILE:-low}"
export K6_LOG_FAILURES="${K6_LOG_FAILURES:-1}"
export K6_OUTPUTS="${K6_OUTPUTS:-experimental-prometheus-rw}"
export K6_PROMETHEUS_RW_TREND_STATS="${K6_PROMETHEUS_RW_TREND_STATS:-p(95),p(99)}"

if [ -z "${ZANN_TEST_RUN_ID:-}" ]; then
  ZANN_TEST_RUN_ID="k6-$(date +%s)-${RANDOM}"
fi
export ZANN_TEST_RUN_ID
if [ -z "${K6_TAG_TEST:-}" ]; then
  K6_TAG_TEST="${ZANN_TEST_RUN_ID}"
fi
export K6_TAG_TEST
if [ -z "${K6_TAG_TEST_RUN_ID:-}" ]; then
  K6_TAG_TEST_RUN_ID="${ZANN_TEST_RUN_ID}"
fi
export K6_TAG_TEST_RUN_ID
echo "K6 test_run_id=${ZANN_TEST_RUN_ID}"

if [ "${heap_clean}" = "1" ]; then
  rm -f "${heap_dir}"/heap-*.heap 2>/dev/null || true
fi

"${script_dir}/reset_db.sh"

PROJECT_NAME="${ZANN_LOADTEST_PROJECT:-zann_loadtest}"
compose_args=()
if [ -n "${PROJECT_NAME}" ]; then
  compose_args=(-p "${PROJECT_NAME}")
fi

heap_profile_auto="${ZANN_HEAP_PROFILE_AUTO:-1}"
heap_profile_dump() {
  local phase="$1"
  if [ "${heap_profile_auto}" = "0" ]; then
    return
  fi
  if ! command -v podman >/dev/null 2>&1; then
    return
  fi
  echo "Requesting heap profile dump (${phase})..."
  podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml \
    kill -s USR1 server >/dev/null 2>&1 || true
}

export ZANN_SERVICE_ACCOUNT_TOKEN="$(cat "${script_dir}/data/loadtest_sa_token")"

if [ -z "${ZANN_ACCESS_TOKEN:-}" ]; then
  admin_email="${ZANN_ADMIN_EMAIL:-loadtest.admin@local.test}"
  admin_password="${ZANN_ADMIN_PASSWORD:-Loadtest123!}"
  login_json=$(curl -s -X POST "${ZANN_BASE_URL}/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${admin_email}\",\"password\":\"${admin_password}\",\"device_name\":\"loadtest\"}")
  login_json_clean=$(printf "%s" "${login_json}" | tr -d '\r')
  if command -v rg >/dev/null 2>&1; then
    ZANN_ACCESS_TOKEN=$(printf "%s" "${login_json_clean}" | rg -o "\"access_token\":\"[^\"]+\"" | head -n 1 | cut -d'"' -f4)
  else
    ZANN_ACCESS_TOKEN=$(printf "%s" "${login_json_clean}" | sed -n 's/.*"access_token":"\\([^"]*\\)".*/\\1/p')
  fi
  export ZANN_ACCESS_TOKEN
  if [ -z "${ZANN_ACCESS_TOKEN}" ]; then
    echo "ERROR: Failed to auto-login for ZANN_ACCESS_TOKEN."
    echo "Response: ${login_json}"
    exit 1
  fi
fi

if [ -z "${ZANN_ACCESS_TOKEN:-}" ]; then
  echo "ERROR: ZANN_ACCESS_TOKEN is required for load tests."
  exit 1
fi

if [ "$#" -lt 1 ]; then
  echo "Usage: K6_SCENARIO=<name> K6_PROFILE=<profile> $0 run loadtest/k6/runner.js"
  exit 1
fi

if [ "${1:-}" = "--" ]; then
  shift
fi

args=("$@")
declare -A seen_tags=()
for ((i = 0; i < ${#args[@]}; i++)); do
  if [ "${args[$i]}" = "--tag" ] && [ $((i + 1)) -lt ${#args[@]} ]; then
    tag="${args[$i + 1]}"
    key="${tag%%=*}"
    seen_tags["$key"]=1
  fi
done

k6_tags=()
if [ -n "${K6_TAG_JOB:-}" ] && [ -z "${seen_tags[job]+x}" ]; then
  k6_tags+=("--tag" "job=${K6_TAG_JOB}")
fi
if [ -n "${K6_TAG_ENV:-}" ] && [ -z "${seen_tags[env]+x}" ]; then
  k6_tags+=("--tag" "env=${K6_TAG_ENV}")
fi
if [ -n "${K6_TAG_INSTANCE:-}" ] && [ -z "${seen_tags[instance]+x}" ]; then
  k6_tags+=("--tag" "instance=${K6_TAG_INSTANCE}")
fi
if [ -n "${K6_TAG_TEST:-}" ] && [ -z "${seen_tags[test]+x}" ]; then
  k6_tags+=("--tag" "test=${K6_TAG_TEST}")
fi
if [ -n "${K6_TAG_TEST_RUN_ID:-}" ] && [ -z "${seen_tags[test_run_id]+x}" ]; then
  k6_tags+=("--tag" "test_run_id=${K6_TAG_TEST_RUN_ID}")
fi

k6_outputs=()
if [ -n "${K6_OUTPUTS:-}" ]; then
  IFS=',' read -r -a output_list <<< "${K6_OUTPUTS}"
  for output in "${output_list[@]}"; do
    if [ -n "${output}" ]; then
      k6_outputs+=("-o" "${output}")
    fi
  done
fi

heap_profile_dump "start"
k6 "${k6_outputs[@]}" "${k6_tags[@]}" "${args[@]}"
status=$?
if [ "${heap_sleep_seconds}" -gt 0 ]; then
  echo "Waiting ${heap_sleep_seconds}s before heap profile dump (end)..."
  sleep "${heap_sleep_seconds}"
fi
heap_profile_dump "end"
exit $status
