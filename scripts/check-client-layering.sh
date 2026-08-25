#!/usr/bin/env bash
#
# Clients go through the facade, and nothing under apps/ is a copy of something
# under crates/. Both rules come from docs/adr/0003-shared-core-layering.md.
#
# The desktop backend became a fork of zann-client because nothing ever compared
# the two trees. This is that comparison. It starts with an allowlist of what is
# already wrong, so it can be switched on today; each migration phase deletes
# entries. An empty allowlist means the migration is done.
#
# The allowlist only shrinks: an entry that no longer violates anything is
# reported as stale and fails the run, so the list cannot quietly outlive the
# problem it documents.

set -euo pipefail

cd "$(dirname "$0")/.."

# Crates a client must not reach past the facade into.
forbidden=(zann_client zann_db zann_crypto zann_keystore)

# Files still importing them. Every entry is a debt with an owner in ADR 0003.
allow_imports=(
  # Ф7 — auth still lives outside the facade, so COSMIC reaches for it directly.
  apps/cosmic/src/backend/remote.rs
  # Ф10 — the facade returns payload JSON, so the client decrypts field kinds.
  apps/cosmic/src/screens/detail.rs
  # Ф4/Ф8/Ф9 — the desktop services have not moved into zann-app yet.
  apps/desktop/src-tauri/src/crypto.rs
  apps/desktop/src-tauri/src/infra/config.rs
  apps/desktop/src-tauri/src/services/auth.rs
  apps/desktop/src-tauri/src/services/backup.rs
  apps/desktop/src-tauri/src/services/items.rs
  apps/desktop/src-tauri/src/services/items_history.rs
  apps/desktop/src-tauri/src/services/session.rs
  apps/desktop/src-tauri/src/services/storage.rs
  apps/desktop/src-tauri/src/services/sync.rs
  apps/desktop/src-tauri/src/services/sync_helpers.rs
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
pattern="use (${pattern%|})|(${pattern%|})"

# ---- rule 1: no reaching past the facade -----------------------------------
seen_imports=()
while IFS= read -r file; do
  # Skip doc comments and plain comments: a crate named in prose is not a use.
  #
  # Not `grep -q` here: it exits on the first match, the upstream grep takes a
  # SIGPIPE, and `set -o pipefail` then reports the whole pipeline as failed —
  # which reads as "no violation" and lets real ones through.
  if grep -vE '^\s*(//|\*)' "$file" | grep -E "$pattern" >/dev/null; then
    seen_imports+=("$file")
    if ! in_list "$file" "${allow_imports[@]}"; then
      echo "error: $file reaches past zann-ffi into a core crate" >&2
      grep -nvE '^\s*(//|\*)' "$file" | grep -E "$pattern" | head -3 >&2
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
