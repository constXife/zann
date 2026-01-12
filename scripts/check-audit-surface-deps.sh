#!/usr/bin/env bash
set -euo pipefail

allowed_deps=(
  argon2
  base64
  blake3
  chacha20poly1305
  hex
  rand
  serde
  serde_json
  sha2
  subtle
  tracing
  uuid
  zeroize
  proptest
)

allowed_pattern=$(printf '%s|' "${allowed_deps[@]}")
allowed_pattern=${allowed_pattern%|}

metadata=$(cargo metadata --format-version 1 --no-deps)

pkg_deps=$(echo "$metadata" | jq -r '.packages[] | select(.name=="zann-crypto") | .dependencies[].name')
if [[ -z "$pkg_deps" ]]; then
  echo "zann-crypto not found in cargo metadata" >&2
  exit 1
fi

bad=$(echo "$pkg_deps" | grep -Ev "^(${allowed_pattern})$" || true)
if [[ -n "$bad" ]]; then
  echo "zann-crypto has disallowed direct dependencies:" >&2
  echo "$bad" | sort -u >&2
  echo "Update scripts/check-audit-surface-deps.sh if intentional." >&2
  exit 1
fi

echo "zann-crypto dependency guard: ok"
