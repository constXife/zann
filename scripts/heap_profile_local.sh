#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

export ZANN_HEAP_PROFILE_DIR="${ZANN_HEAP_PROFILE_DIR:-${repo_root}/.local/heap}"
export ZANN_HEAP_PROFILE_CLEAN="${ZANN_HEAP_PROFILE_CLEAN:-1}"
export JEMALLOC_SYS_WITH_PROF=1
export JEMALLOC_SYS_WITH_MALLOC_CONF="${JEMALLOC_SYS_WITH_MALLOC_CONF:-prof:true,prof_active:false}"
export JEMALLOC_SYS_WITH_CFLAGS="${JEMALLOC_SYS_WITH_CFLAGS:--O2}"
export CFLAGS="${CFLAGS:-${JEMALLOC_SYS_WITH_CFLAGS}}"
export CPPFLAGS="${CPPFLAGS:-${JEMALLOC_SYS_WITH_CFLAGS}}"
export LDFLAGS="${LDFLAGS:-${JEMALLOC_SYS_WITH_CFLAGS}}"
export MALLOC_CONF="prof:true,prof_active:true,prof_accum:true,lg_prof_sample:10,prof_prefix:${ZANN_HEAP_PROFILE_DIR}/heap"
export ZANN_HEAP_PROFILE=1
export ZANN_DB_URL="${ZANN_DB_URL:-postgres://zann:zann@localhost:15432/zann_loadtest}"
export ZANN_ADDR="${ZANN_ADDR:-0.0.0.0:18080}"
export ZANN_METRICS_ENABLED="${ZANN_METRICS_ENABLED:-true}"
export ZANN_METRICS_PROFILE="${ZANN_METRICS_PROFILE:-debug}"
export ZANN_ALLOW_METRICS_DEBUG="${ZANN_ALLOW_METRICS_DEBUG:-true}"
export ZANN_SMK_FILE="${ZANN_SMK_FILE:-${repo_root}/loadtest/data/smk}"
export ZANN_CONFIG_PATH="${ZANN_CONFIG_PATH:-${repo_root}/config/loadtest.yaml}"
export ZANN_PASSWORD_PEPPER="${ZANN_PASSWORD_PEPPER:-dev-pepper}"
export ZANN_TOKEN_PEPPER="${ZANN_TOKEN_PEPPER:-dev-pepper}"
export ZANN_WARMUP_REQUESTS="${ZANN_WARMUP_REQUESTS:-500}"
export ZANN_WARMUP_URLS="${ZANN_WARMUP_URLS:-http://localhost:18080/v1/system/health http://localhost:18080/metrics}"
export ZANN_WARMUP_ADMIN_EMAIL="${ZANN_WARMUP_ADMIN_EMAIL:-loadtest.admin@local.test}"
export ZANN_WARMUP_ADMIN_PASSWORD="${ZANN_WARMUP_ADMIN_PASSWORD:-Loadtest123!}"
export ZANN_WARMUP_VAULT_SLUG="${ZANN_WARMUP_VAULT_SLUG:-warmup-personal}"
export ZANN_WARMUP_ITEMS="${ZANN_WARMUP_ITEMS:-50}"
export ZANN_WARMUP_ITEM_SIZE="${ZANN_WARMUP_ITEM_SIZE:-4096}"
export ZANN_HEAP_PROFILE_AUTO="${ZANN_HEAP_PROFILE_AUTO:-1}"
export ZANN_WARMUP_REGISTER="${ZANN_WARMUP_REGISTER:-0}"
export ZANN_WARMUP_DEVICE_NAME="${ZANN_WARMUP_DEVICE_NAME:-warmup-$(date +%s)}"
export ZANN_WARMUP_VAULT_KEY_BYTES="${ZANN_WARMUP_VAULT_KEY_BYTES:-32}"
export ZANN_HEAP_PROFILE_SLEEP="${ZANN_HEAP_PROFILE_SLEEP:-180}"
export ZANN_HEAP_PROFILE_POST_WARMUP="${ZANN_HEAP_PROFILE_POST_WARMUP:-1}"
export ZANN_HEAP_PROFILE_DIFF="${ZANN_HEAP_PROFILE_DIFF:-1}"
export ZANN_HEAP_PROFILE_RUSTFLAGS="${ZANN_HEAP_PROFILE_RUSTFLAGS:--C debuginfo=2 -C force-frame-pointers=yes}"
if command -v llvm-addr2line >/dev/null 2>&1; then
  export JEPROF_ADDR2LINE="${JEPROF_ADDR2LINE:-llvm-addr2line}"
elif command -v addr2line >/dev/null 2>&1; then
  export JEPROF_ADDR2LINE="${JEPROF_ADDR2LINE:-addr2line}"
fi

mkdir -p "${ZANN_HEAP_PROFILE_DIR}"
if [ ! -w "${ZANN_HEAP_PROFILE_DIR}" ]; then
  fallback_dir="${repo_root}/.local/heap"
  echo "Heap profile dir not writable: ${ZANN_HEAP_PROFILE_DIR}; using ${fallback_dir}"
  ZANN_HEAP_PROFILE_DIR="${fallback_dir}"
  mkdir -p "${ZANN_HEAP_PROFILE_DIR}"
fi
if [ "${ZANN_HEAP_PROFILE_CLEAN}" = "1" ]; then
  rm -f "${ZANN_HEAP_PROFILE_DIR}"/heap-*.heap "${ZANN_HEAP_PROFILE_DIR}"/heap-diff-*.txt 2>/dev/null || true
fi

echo "Building zann-server with jemalloc profiling..."
RUSTFLAGS="${ZANN_HEAP_PROFILE_RUSTFLAGS}" cargo build -p zann-server --features jemalloc

echo "Starting zann-server..."
exec "${repo_root}/target/debug/zann-server" &
server_pid=$!

sleep 1
run_warmup() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl not found; skipping warmup"
    return 0
  fi
  for _ in $(seq 1 "${ZANN_WARMUP_REQUESTS}"); do
    for url in ${ZANN_WARMUP_URLS}; do
      curl -sf "${url}" >/dev/null || true
    done
  done
  if [ "${ZANN_WARMUP_ITEMS}" -le 0 ]; then
    return 0
  fi
  if [ "${ZANN_WARMUP_REGISTER}" = "1" ]; then
    curl -s "${ZANN_ADDR/http:\/\/0.0.0.0/http:\/\/localhost}/v1/auth/register" \
      -H 'Content-Type: application/json' \
      -d "{\"email\":\"${ZANN_WARMUP_ADMIN_EMAIL}\",\"password\":\"${ZANN_WARMUP_ADMIN_PASSWORD}\",\"device_name\":\"${ZANN_WARMUP_DEVICE_NAME}\"}" \
      >/dev/null || true
  fi
  auth_json=$(curl -s "${ZANN_ADDR/http:\/\/0.0.0.0/http:\/\/localhost}/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"email\":\"${ZANN_WARMUP_ADMIN_EMAIL}\",\"password\":\"${ZANN_WARMUP_ADMIN_PASSWORD}\",\"device_name\":\"${ZANN_WARMUP_DEVICE_NAME}\"}")
  access_token=$(printf "%s" "${auth_json}" | rg -o '"access_token":"[^"]+"' | head -n 1 | sed 's/"access_token":"//;s/"$//')
  if [ -z "${access_token}" ]; then
    echo "Warmup login failed; skipping item creation. Response: ${auth_json}"
    return 0
  fi
  vaults_json=$(curl -s "${ZANN_ADDR/http:\/\/0.0.0.0/http:\/\/localhost}/v1/vaults" \
    -H "Authorization: Bearer ${access_token}")
  vault_id=$(printf "%s" "${vaults_json}" | sed -n "s/.*\"id\":\"\\([^\"]*\\)\",\"slug\":\"${ZANN_WARMUP_VAULT_SLUG}\".*/\\1/p")
  if [ -z "${vault_id}" ]; then
    vault_key_enc=$(head -c "${ZANN_WARMUP_VAULT_KEY_BYTES}" /dev/urandom | od -An -tu1 -v | tr -s ' ' | tr ' ' ',' | tr -d '\n' | sed 's/^,//;s/,$//')
    create_json=$(curl -s -X POST "${ZANN_ADDR/http:\/\/0.0.0.0/http:\/\/localhost}/v1/vaults" \
      -H "Authorization: Bearer ${access_token}" \
      -H 'Content-Type: application/json' \
      -d "{\"slug\":\"${ZANN_WARMUP_VAULT_SLUG}\",\"name\":\"Warmup Vault\",\"kind\":1,\"cache_policy\":1,\"vault_key_enc\":[${vault_key_enc}]}")
    vault_id=$(printf "%s" "${create_json}" | sed -n 's/.*"id":"\\([^"]*\\)".*/\\1/p')
  fi
  if [ -z "${vault_id}" ]; then
    echo "Warmup vault not available; skipping item creation."
    return 0
  fi
  payload_enc=$(head -c "${ZANN_WARMUP_ITEM_SIZE}" /dev/urandom | od -An -tu1 -v | tr -s ' ' | tr ' ' ',' | tr -d '\n' | sed 's/^,//;s/,$//')
  created=0
  for i in $(seq 1 "${ZANN_WARMUP_ITEMS}"); do
    item_name="warmup-${i}"
    item_json=$(printf '{"path":"warmup/%s","name":"%s","type_id":"login","payload_enc":[%s],"checksum":"warmup"}' "${item_name}" "${item_name}" "${payload_enc}")
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${ZANN_ADDR/http:\/\/0.0.0.0/http:\/\/localhost}/v1/vaults/${vault_id}/items" \
      -H "Authorization: Bearer ${access_token}" \
      -H 'Content-Type: application/json' \
      -d "${item_json}")
    if [ "${status}" = "201" ]; then
      created=$((created + 1))
    fi
  done
  echo "Warmup items created: ${created}/${ZANN_WARMUP_ITEMS}"
}

run_warmup

if [ "${ZANN_HEAP_PROFILE_AUTO}" = "1" ]; then
  base_heap=""
  if [ "${ZANN_HEAP_PROFILE_DIFF}" = "1" ]; then
    echo "Capturing base heap profile..."
    kill -USR1 "${server_pid}" || true
    sleep 1
    base_heap="$(ls -1t "${ZANN_HEAP_PROFILE_DIR}"/heap-*.heap 2>/dev/null | head -n 1 || true)"
    if [ -n "${base_heap}" ]; then
      echo "Base heap profile: ${base_heap}"
    fi
  fi
  if [ "${ZANN_HEAP_PROFILE_SLEEP}" -gt 0 ]; then
    echo "Waiting ${ZANN_HEAP_PROFILE_SLEEP}s before heap dump..."
    sleep "${ZANN_HEAP_PROFILE_SLEEP}"
  fi
  if [ "${ZANN_HEAP_PROFILE_POST_WARMUP}" = "1" ]; then
    echo "Running post-base warmup..."
    run_warmup
  fi
  echo "Requesting heap profile dump..."
  kill -USR1 "${server_pid}" || true
  if [ "${ZANN_HEAP_PROFILE_DIFF}" = "1" ] && [ -n "${base_heap}" ]; then
    sleep 1
    new_heap="$(ls -1t "${ZANN_HEAP_PROFILE_DIR}"/heap-*.heap 2>/dev/null | head -n 1 || true)"
    if [ -n "${new_heap}" ] && [ "${new_heap}" != "${base_heap}" ]; then
      report="${ZANN_HEAP_PROFILE_DIR}/heap-diff-$(date +%s).txt"
      if command -v jeprof >/dev/null 2>&1; then
        if ! command -v addr2line >/dev/null 2>&1 && ! command -v llvm-addr2line >/dev/null 2>&1; then
          echo "addr2line not found; jeprof output may show raw addresses."
        fi
        echo "Writing heap diff report to ${report}"
        jeprof --show_bytes --text --lines "${repo_root}/target/debug/zann-server" \
          --base="${base_heap}" \
          "${new_heap}" > "${report}" 2>&1 || true
        if rg -q "Total:" "${report}"; then
          echo "Heap diff (top 80 lines):"
          sed -n '1,80p' "${report}" || true
        else
          echo "Heap diff report did not include totals; writing latest heap report."
          latest_report="${ZANN_HEAP_PROFILE_DIR}/heap-latest-$(date +%s).txt"
          jeprof --show_bytes --text --lines "${repo_root}/target/debug/zann-server" \
            "${new_heap}" > "${latest_report}" 2>&1 || true
          sed -n '1,80p' "${latest_report}" || true
        fi
      fi
    fi
  fi
fi

kill "${server_pid}" >/dev/null 2>&1 || true

wait "${server_pid}"
