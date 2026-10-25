#!/usr/bin/env bash
#
# Shells under apps/ must not reach directly into low-level infrastructure or
# non-composition modules, and no file under apps/ may be a byte-identical copy
# of a file under crates/. Governed by docs/adr/0001-shared-client-core.md and
# docs/architecture/capabilities.md (complementing check-client-architecture.sh).
#
# The allowlist only shrinks: an entry that no longer matches is reported as
# stale and fails the run, so the list cannot quietly outlive the migration
# debt it documents.

set -euo pipefail

cd "$(dirname "$0")/.."

# Crates a client must not reach past the facade into.
forbidden=(zann_db zann_crypto zann_keystore)

# Files still importing them. Every entry is a debt with an owner in ADR 0003.
allow_imports=(
  # COSMIC native composition root for the canonical application client.
  apps/cosmic/src/backend/remote.rs
  # Ф4 — desktop composition root for AppClient sync; remaining services are still a fork.
  apps/desktop/src-tauri/src/crypto.rs
  apps/desktop/src-tauri/src/infra/config.rs
  apps/desktop/src-tauri/src/infra/sync_client.rs
  apps/desktop/src-tauri/src/services/auth.rs
  apps/desktop/src-tauri/src/services/backup.rs
  apps/desktop/src-tauri/src/services/items.rs
  apps/desktop/src-tauri/src/services/items_history.rs
  apps/desktop/src-tauri/src/services/session.rs
  apps/desktop/src-tauri/src/services/storage.rs
  apps/desktop/src-tauri/src/services/sync.rs
  apps/desktop/src-tauri/src/services/vaults.rs
  apps/desktop/src-tauri/src/state.rs
  apps/desktop/src-tauri/src/types.rs
)

# Files byte-identical to one under crates/. Ф2 deletes all three.
allow_copies=(
)

in_list() {
  local needle=$1; shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

failed=0
pattern=$(printf '%s::|' "${forbidden[@]}")
pattern="zann_client::(?!app::local::)|(${pattern%|})"

# ---- rule 1: no reaching past the facade -----------------------------------
seen_imports=()
while IFS= read -r file; do
  # Skip doc comments and plain comments: a crate named in prose is not a use.
  #
  # Not `grep -q` here: it exits on the first match, the upstream grep takes a
  # SIGPIPE, and `set -o pipefail` then reports the whole pipeline as failed —
  # which reads as "no violation" and lets real ones through.
  if grep -vE '^\s*(//|\*)' "$file" | rg --pcre2 "$pattern" >/dev/null; then
    seen_imports+=("$file")
    if ! in_list "$file" "${allow_imports[@]}"; then
      echo "error: $file reaches beyond an application port" >&2
      grep -nvE '^\s*(//|\*)' "$file" | rg --pcre2 "$pattern" | head -3 >&2
      failed=1
    fi
  fi
done < <(find apps -name '*.rs' -not -path '*/target/*' | sort)

# ---- rule 2: no file under apps/ is a copy of one under crates/ ------------
#
# Compared by content, not by name: a fork that gets renamed on the way out is
# still a fork, and matching basenames would miss exactly that.
declare -A crate_by_hash=()
while IFS= read -r candidate; do
  hash=$(sha256sum "$candidate" | cut -d' ' -f1)
  crate_by_hash["$hash"]="$candidate"
done < <(find crates -name '*.rs' -not -path '*/target/*' | sort)

seen_copies=()
while IFS= read -r file; do
  hash=$(sha256sum "$file" | cut -d' ' -f1)
  origin=${crate_by_hash["$hash"]:-}
  [[ -n "$origin" ]] || continue
  seen_copies+=("$file")
  if ! in_list "$file" "${allow_copies[@]}"; then
    echo "error: $file is byte-identical to $origin" >&2
    failed=1
  fi
done < <(find apps -name '*.rs' -not -path '*/target/*' | sort)

# ---- the allowlist may only shrink ----------------------------------------
for entry in "${allow_imports[@]}"; do
  if ! in_list "$entry" "${seen_imports[@]+"${seen_imports[@]}"}"; then
    echo "error: stale allowlist entry (no longer violates): $entry" >&2
    echo "       remove it from allow_imports in $0" >&2
    failed=1
  fi
done
for entry in "${allow_copies[@]}"; do
  if ! in_list "$entry" "${seen_copies[@]+"${seen_copies[@]}"}"; then
    echo "error: stale allowlist entry (no longer a copy): $entry" >&2
    echo "       remove it from allow_copies in $0" >&2
    failed=1
  fi
done

if [[ "$failed" -eq 0 ]]; then
  echo "client layering ok (${#allow_imports[@]} imports and ${#allow_copies[@]} copies still owed)"
fi
exit "$failed"
