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
export K6_PROFILE="${K6_PROFILE:-low}"
export K6_SCENARIO="${K6_SCENARIO:-baseline_normal}"
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

if [ -z "${ZANN_SERVICE_ACCOUNT_TOKEN:-}" ] && [ -f "${script_dir}/data/loadtest_sa_token" ]; then
  ZANN_SERVICE_ACCOUNT_TOKEN="$(cat "${script_dir}/data/loadtest_sa_token")"
  export ZANN_SERVICE_ACCOUNT_TOKEN
fi

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <k6-args...>"
  echo "Example: K6_SCENARIO=baseline_normal K6_PROFILE=normal $0 run loadtest/k6/runner.js"
  exit 1
fi

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

exec k6 "${k6_outputs[@]}" "${k6_tags[@]}" "${args[@]}"
