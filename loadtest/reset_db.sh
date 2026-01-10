#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${ZANN_BASE_URL:-http://localhost:18080}"
PROJECT_NAME="${ZANN_LOADTEST_PROJECT:-zann_loadtest}"
ADMIN_EMAIL="${ZANN_ADMIN_EMAIL:-loadtest.admin@local.test}"
ADMIN_PASSWORD="${ZANN_ADMIN_PASSWORD:-Loadtest123!}"
LOADTEST_VAULT_SLUG="${ZANN_LOADTEST_VAULT_SLUG:-loadtest}"
LOADTEST_VAULT_NAME="${ZANN_LOADTEST_VAULT_NAME:-Loadtest Shared}"
LOADTEST_VAULT_CACHE_POLICY="${ZANN_LOADTEST_VAULT_CACHE_POLICY:-full}"
TOKEN_OUT="${ZANN_LOADTEST_TOKEN_OUT:-./loadtest/data/loadtest_sa_token}"
RESET_DB="${ZANN_LOADTEST_RESET_DB:-1}"

compose_args=()
if [ -n "${PROJECT_NAME}" ]; then
  compose_args=(-p "${PROJECT_NAME}")
fi

project_name="${PROJECT_NAME}"
volume_name="${project_name}_zann_pgdata_loadtest"

if [ "${RESET_DB}" = "1" ]; then
  echo "Resetting loadtest DB..."
  if command -v podman >/dev/null 2>&1; then
    echo "Stopping any containers holding port 15432..."
    conflict_ids=$(podman ps --format '{{.ID}} {{.Names}} {{.Ports}}' | rg '0\\.0\\.0\\.0:15432' | awk '{print $1}' || true)
    if [ -n "${conflict_ids}" ]; then
      podman rm -f ${conflict_ids} >/dev/null 2>&1 || true
    fi
    extra_ids=$(podman ps --format '{{.ID}} {{.Names}}' | rg 'db_loadtest' | awk '{print $1}' || true)
    if [ -n "${extra_ids}" ]; then
      podman rm -f ${extra_ids} >/dev/null 2>&1 || true
    fi
    podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml down -v --remove-orphans >/dev/null 2>&1 || true
    echo "Clearing loadtest data (smk, tokens)..."
    podman unshare rm -f ./loadtest/data/smk ./loadtest/data/loadtest_sa_token >/dev/null 2>&1 || true
    podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml stop server migrate db_loadtest >/dev/null 2>&1 || true
    podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml rm -f db_loadtest >/dev/null 2>&1 || true
    for vol in $(podman volume ls --format '{{.Name}}' | rg 'zann_pgdata_loadtest$' || true); do
      containers=$(podman ps -a --filter volume="${vol}" --format '{{.ID}}' || true)
      if [ -n "${containers}" ]; then
        podman rm -f ${containers} >/dev/null 2>&1 || true
      fi
      podman volume rm "${vol}" >/dev/null 2>&1 || true
    done
    podman volume rm "${volume_name}" >/dev/null 2>&1 || true
    podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml up -d db_loadtest >/dev/null
    echo "Waiting for loadtest DB..."
    until podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml exec -T db_loadtest \
      pg_isready -U zann -d zann_loadtest >/dev/null 2>&1; do
      sleep 1
    done
    echo "Running migrations..."
    podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml run --rm migrate migrate >/dev/null
    podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml up -d server >/dev/null
  fi
fi

echo "Waiting for loadtest server at ${BASE_URL}..."
until curl -s "${BASE_URL}/health" >/dev/null 2>&1; do
  sleep 1
done

echo "Creating admin user (idempotent)..."
curl -s "${BASE_URL}/v1/auth/register" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\",\"device_name\":\"loadtest\"}" \
  >/dev/null || true

echo "Logging in to fetch access token..."
auth_json=$(curl -s "${BASE_URL}/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${ADMIN_EMAIL}\",\"password\":\"${ADMIN_PASSWORD}\",\"device_name\":\"loadtest\"}")
if [ -z "${auth_json}" ]; then
  echo "Login failed: empty response."
  exit 1
fi
access_token=$(printf "%s" "${auth_json}" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')

if [ -z "${access_token}" ]; then
  echo "Failed to get access token. Response was: ${auth_json}"
  exit 1
fi

echo "Ensuring shared loadtest vault..."
vaults_json=$(curl -s "${BASE_URL}/v1/vaults" \
  -H "Authorization: Bearer ${access_token}")
vault_id=$(printf "%s" "${vaults_json}" | sed -n "s/.*\"id\":\"\\([^\"]*\\)\",\"slug\":\"${LOADTEST_VAULT_SLUG}\".*/\\1/p")
if [ -z "${vault_id}" ]; then
  vault_id=$(printf "%s" "${vaults_json}" | sed -n "s/.*\"slug\":\"${LOADTEST_VAULT_SLUG}\",\"name\"[^}]*\"id\":\"\\([^\"]*\\)\".*/\\1/p")
fi

if [ -z "${vault_id}" ]; then
  create_json=$(curl -s -X POST "${BASE_URL}/v1/vaults" \
    -H "Authorization: Bearer ${access_token}" \
    -H 'Content-Type: application/json' \
    -d "{\"slug\":\"${LOADTEST_VAULT_SLUG}\",\"name\":\"${LOADTEST_VAULT_NAME}\",\"kind\":\"shared\",\"cache_policy\":\"${LOADTEST_VAULT_CACHE_POLICY}\"}")
  vault_id=$(printf "%s" "${create_json}" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
fi

if [ -z "${vault_id}" ]; then
  echo "Failed to resolve or create loadtest vault."
  exit 1
fi

echo "Creating service-account token..."
token_dir="$(dirname "${TOKEN_OUT}")"
if [ ! -d "${token_dir}" ]; then
  mkdir -p "${token_dir}" 2>/dev/null || true
fi
if [ ! -w "${token_dir}" ]; then
  if command -v podman >/dev/null 2>&1; then
    echo "Fixing permissions via podman unshare..."
    podman unshare chown -R "$(id -u):$(id -g)" "${token_dir}" || true
    podman unshare chmod -R u+rwX "${token_dir}" || true
    podman unshare chmod -R a+rwX "${token_dir}" || true
  fi
fi
if [ ! -w "${token_dir}" ]; then
  echo "Token path not writable: ${TOKEN_OUT}."
  echo "Try: podman unshare chmod -R a+rwX ${token_dir}"
  exit 1
fi
sa_json=$(podman compose "${compose_args[@]}" -f compose.yaml -f compose.loadtest.yaml exec -T server \
  /app/zann-server tokens create \
  --name "k6" \
  --vault "${LOADTEST_VAULT_SLUG}" \
  --prefix / \
  --ops read \
  --ttl 30d \
  --issued-by-email "${ADMIN_EMAIL}")
sa_token=$(printf "%s" "${sa_json}" | tr -d '\r' | rg -o "zann_sa_[A-Za-z0-9]+" | tail -n 1)

if [ -z "${sa_token}" ]; then
  echo "Failed to create service-account token. Response was: ${sa_json}"
  exit 1
fi

echo "${sa_token}" > "${TOKEN_OUT}"
chmod 600 "${TOKEN_OUT}"

echo "Done."
