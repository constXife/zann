#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
engine="${1:-docker}"
if (( $# > 0 )); then shift; fi
case "$engine" in
  docker|podman) ;;
  *) echo "Usage: $0 [docker|podman] [SERVICE ...]" >&2; exit 1 ;;
esac

"$engine" compose version >/dev/null

if [[ -L .env || ( -e .env && ! -f .env ) ]]; then
  echo '.env must be a regular file, not a symlink' >&2
  exit 1
fi

if [[ ! -e .env ]]; then
  umask 077
  env_tmp="$(mktemp .env.XXXXXX)"
  trap 'rm -f "$env_tmp"' EXIT
  password_pepper="$(openssl rand -base64 32)"
  token_pepper="$(openssl rand -base64 32)"
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ZANN_PASSWORD_PEPPER=) printf 'ZANN_PASSWORD_PEPPER=%s\n' "$password_pepper" ;;
      ZANN_TOKEN_PEPPER=) printf 'ZANN_TOKEN_PEPPER=%s\n' "$token_pepper" ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < .env.example > "$env_tmp"
  # Publish only the complete file; refuse to replace a concurrently created .env.
  ln "$env_tmp" .env
  rm -f "$env_tmp"
  trap - EXIT
  unset password_pepper token_pepper
  echo 'Created .env (0600); keep it for subsequent starts.'
fi
chmod 600 .env

exec "$engine" compose up -d --build "$@"
