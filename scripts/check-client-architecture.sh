#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
boundaries_file="$repo_root/config/architecture-boundaries.json"

for command_name in cargo jq rg tsort; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "client architecture guard requires '$command_name'" >&2
    exit 2
  fi
done

if [[ ! -f "$boundaries_file" ]]; then
  echo "missing architecture boundary config: $boundaries_file" >&2
  exit 2
fi

if ! jq -e '.schema_version == 1' "$boundaries_file" >/dev/null; then
  echo "unsupported architecture boundary schema" >&2
  exit 2
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
packages_json="$tmp_dir/packages.json"
package_lines="$tmp_dir/packages.jsonl"
violations="$tmp_dir/violations"
touch "$package_lines" "$violations"

record_violation() {
  echo "$*" >> "$violations"
}

exception_exists() {
  local package_name=$1
  local dependency_name=$2
  jq -e \
    --arg package "$package_name" \
    --arg dependency "$dependency_name" \
    '.dependency_exceptions[] | select(.package == $package and .dependency == $dependency)' \
    "$boundaries_file" >/dev/null
}

validate_exception_metadata() {
  local invalid
  invalid=$(jq -r '
    .exceptions
    | to_entries[]
    | select(
        (.value.owner | type != "string" or length == 0)
        or (.value.tracking | type != "string" or length == 0)
        or (.value.removal_condition | type != "string" or length == 0)
        or (.value.grandfathered | type != "boolean")
        or (
          (.value.grandfathered | not)
          and (
            (.value.issue | type != "string" or test("^(https://|#[0-9]+$)") | not)
            or (.value.expires_on | type != "string" or test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$") | not)
          )
        )
        or (
          .value.grandfathered
          and (
            (.value.tracking | test("^ADR-0001 phase [0-9]+$") | not)
            or (.value.review_on | type != "string" or test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$") | not)
          )
        )
      )
    | .key
  ' "$boundaries_file")
  if [[ -n "$invalid" ]]; then
    record_violation "exceptions with incomplete owner/tracking/review/expiry metadata: $(tr '\n' ' ' <<<"$invalid")"
  fi

  local expired today
  today=$(date -u +%F)
  expired=$(jq -r --arg today "$today" '
    .exceptions
    | to_entries[]
    | select((.value.grandfathered | not) and .value.expires_on < $today)
    | .key
  ' "$boundaries_file")
  if [[ -n "$expired" ]]; then
    record_violation "expired architecture exceptions: $(tr '\n' ' ' <<<"$expired")"
  fi

  local overdue_reviews
  overdue_reviews=$(jq -r --arg today "$today" '
    .exceptions
    | to_entries[]
    | select(.value.grandfathered and .value.review_on < $today)
    | .key
  ' "$boundaries_file")
  if [[ -n "$overdue_reviews" ]]; then
    record_violation "grandfathered exceptions due for review: $(tr '\n' ' ' <<<"$overdue_reviews")"
  fi

  local missing_reference
  missing_reference=$(jq -r '
    . as $config
    |
    [
      .dependency_exceptions[].id,
      .feature_exceptions[].id,
      .source_rules[].exception_ids[]
    ]
    | unique[] as $id
    | select($config.exceptions[$id] == null)
    | $id
  ' "$boundaries_file")
  if [[ -n "$missing_reference" ]]; then
    record_violation "unknown exception references: $(tr '\n' ' ' <<<"$missing_reference")"
  fi
}

collect_metadata() {
  local manifest
  while IFS= read -r manifest; do
    local manifest_path="$repo_root/$manifest"
    if [[ ! -f "$manifest_path" ]]; then
      record_violation "configured manifest does not exist: $manifest"
      continue
    fi
    if ! cargo metadata \
      --manifest-path "$manifest_path" \
      --format-version 1 \
      --locked \
      --no-deps \
      | jq -c '.packages[]' >> "$package_lines"; then
      echo "cargo metadata failed for $manifest" >&2
      exit 2
    fi
  done < <(jq -r '.manifests[]' "$boundaries_file")

  jq -s 'sort_by(.name) | unique_by(.name)' "$package_lines" > "$packages_json"
}

check_package_coverage() {
  local package_name
  while IFS= read -r package_name; do
    if ! jq -e --arg package "$package_name" '.allowed_internal_dependencies[$package] != null' "$boundaries_file" >/dev/null; then
      record_violation "package '$package_name' is missing from allowed_internal_dependencies"
    fi
  done < <(jq -r '.[].name' "$packages_json")

  while IFS= read -r package_name; do
    if ! jq -e --arg package "$package_name" '.[] | select(.name == $package)' "$packages_json" >/dev/null; then
      record_violation "configured internal package '$package_name' was not found in any manifest"
    fi
  done < <(jq -r '.internal_packages[]' "$boundaries_file")

  local dependency_name
  while IFS=$'\t' read -r package_name dependency_name; do
    if ! jq -e --arg dependency "$dependency_name" '.internal_packages | index($dependency) != null' "$boundaries_file" >/dev/null; then
      record_violation "unclassified local dependency: $package_name -> $dependency_name"
    fi
  done < <(jq -r '.[] | .name as $package | .dependencies[] | select(.path != null) | [$package, .name] | @tsv' "$packages_json")
}

check_dependencies() {
  local graph_edges="$tmp_dir/internal-edges"
  touch "$graph_edges"

  local package_name dependency_name
  while IFS=$'\t' read -r package_name dependency_name; do
    [[ -z "$package_name" || -z "$dependency_name" ]] && continue

    if jq -e --arg dependency "$dependency_name" '.internal_packages | index($dependency) != null' "$boundaries_file" >/dev/null; then
      echo "$package_name $dependency_name" >> "$graph_edges"
      if ! jq -e \
        --arg package "$package_name" \
        --arg dependency "$dependency_name" \
        '.allowed_internal_dependencies[$package] | index($dependency) != null' \
        "$boundaries_file" >/dev/null \
        && ! exception_exists "$package_name" "$dependency_name"; then
        record_violation "forbidden internal dependency: $package_name -> $dependency_name"
      fi
    fi

    if jq -e \
      --arg package "$package_name" \
      --arg dependency "$dependency_name" \
      '.forbidden_direct_dependencies[$package] // [] | index($dependency) != null' \
      "$boundaries_file" >/dev/null \
      && ! exception_exists "$package_name" "$dependency_name"; then
      record_violation "forbidden direct dependency: $package_name -> $dependency_name"
    fi

    if jq -e --arg package "$package_name" '.shared_packages | index($package) != null' "$boundaries_file" >/dev/null \
      && jq -e --arg dependency "$dependency_name" '.forbidden_shared_dependencies | index($dependency) != null' "$boundaries_file" >/dev/null; then
      record_violation "UI/shell dependency leaked into shared crate: $package_name -> $dependency_name"
    fi
  done < <(jq -r '.[] | .name as $package | .dependencies[] | [$package, .name] | @tsv' "$packages_json")

  if [[ -s "$graph_edges" ]] && ! tsort "$graph_edges" >/dev/null 2>&1; then
    record_violation "cycle detected in internal package dependency graph"
  fi

  local exception_id
  while IFS=$'\t' read -r exception_id package_name dependency_name; do
    if ! jq -e \
      --arg package "$package_name" \
      --arg dependency "$dependency_name" \
      '.[] | select(.name == $package) | .dependencies[] | select(.name == $dependency)' \
      "$packages_json" >/dev/null; then
      record_violation "stale dependency exception $exception_id: $package_name -> $dependency_name no longer exists"
    fi
  done < <(jq -r '.dependency_exceptions[] | [.id, .package, .dependency] | @tsv' "$boundaries_file")
}

check_features() {
  if jq -e '
    .[]
    | select(.name == "zann-client")
    | .dependencies[]
    | select(.name | test("^(anyhow|blake3|dirs|zann-db)$"))
  ' "$packages_json" >/dev/null; then
    record_violation "clean zann-client must not declare legacy config/local dependencies"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-client")
    | .features
    | keys[]
    | select(test("^(legacy-config|legacy-local|local)$"))
  ' "$packages_json" >/dev/null; then
    record_violation "clean zann-client must not declare legacy compatibility features"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-client")
    | (.features.default // [])[]?
    | select(test("(^|[:/])(local|sqlite|zann-db)($|[:/])"))
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client default features must not enable local storage or SQLite"
  fi

  if ! jq -e '
    .[]
    | select(.name == "zann-client")
    | .features.default == ["remote"]
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client must default to the remote surface only; config and local are opt-in"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-client")
    | (.features.remote // [])[]?
    | select(test("(^|[:/])(local|sqlite|zann-db|os-credentials|zann-keystore)($|[:/])"))
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client remote feature must not enable local storage, SQLite or OS credentials"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-client")
    | (.features.config // [])[]?
    | select(test("(^|[:/])(legacy-config|legacy-local|local|sqlite|zann-db|os-credentials|zann-keystore)($|[:/])"))
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client config feature must not enable legacy config/local storage, SQLite or OS credentials"
  fi

  if rg -q 'legacy-(config|local)|feature = "local"|pub mod (auth|auth_oidc|auth_password|http|state|tokens)' \
    "$repo_root/crates/zann-client/Cargo.toml" \
    "$repo_root/crates/zann-client/src/lib.rs"; then
    record_violation "clean zann-client manifest or root exposes a legacy compatibility surface"
  fi

  if ! jq -e '
    .[]
    | select(.name == "zann-client")
    | ((.features["os-credentials"] // []) | index("config") != null)
      and ((.features["os-credentials"] // []) | index("dep:zann-keystore") != null)
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client os-credentials feature must compose config with zann-keystore explicitly"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-client")
    | (.features["os-credentials"] // [])[]?
    | select(test("(^|[:/])(local|sqlite|zann-db)($|[:/])"))
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client os-credentials feature must not enable local storage or SQLite"
  fi

  if ! jq -e '
    .[]
    | select(.name == "zann-client")
    | .dependencies[]
    | select(.name == "zann-keystore")
    | .uses_default_features == false
      and .features == ["secret-store"]
  ' "$packages_json" >/dev/null; then
    record_violation "zann-client -> zann-keystore must disable defaults and select only secret-store"
  fi

  local contract_count contract_index contract_package contract_feature
  contract_count=$(jq '.feature_contracts | length' "$boundaries_file")
  for ((contract_index = 0; contract_index < contract_count; contract_index++)); do
    contract_package=$(jq -r ".feature_contracts[$contract_index].package" "$boundaries_file")
    contract_feature=$(jq -r ".feature_contracts[$contract_index].feature" "$boundaries_file")

    if ! jq -e \
      --arg package "$contract_package" \
      --arg feature "$contract_feature" \
      '.[] | select(.name == $package) | .features[$feature] != null' \
      "$packages_json" >/dev/null; then
      record_violation "$contract_package is missing its contracted $contract_feature feature"
      continue
    fi

    local required_member forbidden_member
    while IFS= read -r required_member; do
      if ! jq -e \
        --arg package "$contract_package" \
        --arg feature "$contract_feature" \
        --arg member "$required_member" \
        '.[] | select(.name == $package) | .features[$feature] | index($member) != null' \
        "$packages_json" >/dev/null; then
        record_violation "$contract_package $contract_feature feature must compose $required_member explicitly"
      fi
    done < <(jq -r ".feature_contracts[$contract_index].required_members[]" "$boundaries_file")

    while IFS= read -r forbidden_member; do
      if jq -e \
        --arg package "$contract_package" \
        --arg feature "$contract_feature" \
        --arg member "$forbidden_member" \
        '.[] | select(.name == $package) | .features[$feature] | index($member) != null' \
        "$packages_json" >/dev/null; then
        record_violation "$contract_package $contract_feature feature must not compose $forbidden_member"
      fi
    done < <(jq -r ".feature_contracts[$contract_index].forbidden_members[]" "$boundaries_file")

    local contract_tree="$tmp_dir/$contract_package-$contract_feature-contract-tree"
    if ! cargo tree \
      --manifest-path "$repo_root/Cargo.toml" \
      --package "$contract_package" \
      --no-default-features \
      --features "$contract_feature" \
      --edges normal \
      --prefix none \
      --format '{p}' \
      --locked > "$contract_tree"; then
      echo "cargo tree failed for the $contract_package $contract_feature contract" >&2
      exit 2
    fi

    local forbidden_contract_package
    while IFS= read -r forbidden_contract_package; do
      if rg -q "^${forbidden_contract_package} v" "$contract_tree"; then
        record_violation "$contract_package $contract_feature dependency closure contains $forbidden_contract_package"
      fi
    done < <(jq -r ".feature_contracts[$contract_index].forbidden_packages[]" "$boundaries_file")
  done

  local client_surface surface_label surface_tree forbidden_surface_package
  for client_surface in remote config remote,config; do
    surface_label=${client_surface//,/+}
    surface_tree="$tmp_dir/zann-client-$surface_label-tree"
    if ! cargo tree \
      --manifest-path "$repo_root/Cargo.toml" \
      --package zann-client \
      --no-default-features \
      --features "$client_surface" \
      --edges normal \
      --prefix none \
      --format '{p}' \
      --locked > "$surface_tree"; then
      echo "cargo tree failed for the zann-client $surface_label surface" >&2
      exit 2
    fi
    for forbidden_surface_package in zann-db sqlx-sqlite libsqlite3-sys zann-keystore keyring; do
      if rg -q "^${forbidden_surface_package} v" "$surface_tree"; then
        record_violation "zann-client $surface_label dependency closure contains $forbidden_surface_package"
      fi
    done
  done

  local credential_tree="$tmp_dir/zann-client-os-credentials-tree"
  if ! cargo tree \
    --manifest-path "$repo_root/Cargo.toml" \
    --package zann-client \
    --no-default-features \
    --features os-credentials \
    --edges normal \
    --prefix none \
    --format '{p}' \
    --locked > "$credential_tree"; then
    echo "cargo tree failed for the zann-client os-credentials surface" >&2
    exit 2
  fi
  for forbidden_surface_package in zann-db sqlx-sqlite libsqlite3-sys ctap-hid-fido2 hidapi; do
    if rg -q "^${forbidden_surface_package} v" "$credential_tree"; then
      record_violation "zann-client os-credentials dependency closure contains $forbidden_surface_package"
    fi
  done

  local credential_feature_tree="$tmp_dir/zann-client-os-credentials-feature-tree"
  if ! cargo tree \
    --manifest-path "$repo_root/Cargo.toml" \
    --package zann-client \
    --no-default-features \
    --features os-credentials \
    --edges normal \
    --prefix none \
    --format $'{p}\t{f}' \
    --locked > "$credential_feature_tree"; then
    echo "cargo tree failed to inspect zann-keystore features for os-credentials" >&2
    exit 2
  fi
  local enabled_keystore_features
  enabled_keystore_features=$(awk -F $'\t' '$1 ~ /^zann-keystore v/ { print $2; exit }' "$credential_feature_tree")
  if [[ -z "$enabled_keystore_features" ]]; then
    record_violation "zann-client os-credentials dependency closure is missing zann-keystore"
  elif tr ',' '\n' <<<"$enabled_keystore_features" | rg -q '^(default|full|remembered|fido)$'; then
    record_violation "zann-client os-credentials enables non-thin zann-keystore features: $enabled_keystore_features"
  elif ! tr ',' '\n' <<<"$enabled_keystore_features" | rg -q '^secret-store$'; then
    record_violation "zann-client os-credentials must enable zann-keystore secret-store"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-cli")
    | .dependencies[]
    | select(.name == "zann-client")
    | .features[]?
    | select(test("local|sqlite|zann-db"))
  ' "$packages_json" >/dev/null; then
    record_violation "zann-cli must use only the remote zann-client surface"
  fi

  if jq -e '
    .[]
    | select(.name == "zann-cli")
    | .dependencies[]
    | select(.name == "zann-client")
  ' "$packages_json" >/dev/null; then
    if ! jq -e '
      .[]
      | select(.name == "zann-cli")
      | .dependencies[]
      | select(.name == "zann-client")
      | .uses_default_features == false
    ' "$packages_json" >/dev/null; then
      record_violation "zann-cli -> zann-client must disable default features"
    fi
    if ! jq -e '
      .[]
      | select(.name == "zann-cli")
      | .dependencies[]
      | select(.name == "zann-client")
      | .features | index("remote") != null
    ' "$packages_json" >/dev/null; then
      record_violation "zann-cli -> zann-client must select the remote feature explicitly"
    fi
  fi

  if jq -e '
    .[]
    | select(.name == "zann-client-legacy"
        or any(.dependencies[]?; .name == "zann-client-legacy" and .kind == null))
  ' "$packages_json" >/dev/null; then
    record_violation "removed zann-client-legacy package or dependency reappeared"
  fi

  if ! jq -e '
    .[]
    | select(.name == "zann-ffi")
    | any(.dependencies[]?;
        .name == "zann-client"
        and .kind == null
        and (.features | index("app") != null)
        and (.features | index("os-credentials") != null))
  ' "$packages_json" >/dev/null; then
    record_violation "zann-ffi must consume the canonical zann-client app surface"
  fi
}

check_source_rules() {
  local rule_count rule_index
  rule_count=$(jq '.source_rules | length' "$boundaries_file")
  for ((rule_index = 0; rule_index < rule_count; rule_index++)); do
    local name pattern expected_count matches_file current_files expected_files
    name=$(jq -r ".source_rules[$rule_index].name" "$boundaries_file")
    pattern=$(jq -r ".source_rules[$rule_index].pattern" "$boundaries_file")
    expected_count=$(jq -r ".source_rules[$rule_index].max_matches" "$boundaries_file")
    matches_file="$tmp_dir/source-$rule_index"
    current_files="$tmp_dir/source-$rule_index-files"
    expected_files="$tmp_dir/source-$rule_index-expected"

    local roots=() root
    while IFS= read -r root; do
      roots+=("$root")
    done < <(jq -r ".source_rules[$rule_index].roots[] | \"$repo_root/\" + ." "$boundaries_file")
    local rg_status=0
    rg --count-matches --no-messages -- "$pattern" "${roots[@]}" > "$matches_file" || rg_status=$?
    if ((rg_status > 1)); then
      record_violation "source rule '$name' failed to scan (rg exit $rg_status)"
      continue
    fi

    sed "s#^$repo_root/##" "$matches_file" | cut -d: -f1 | sort -u > "$current_files"
    jq -r ".source_rules[$rule_index].allowed_files[]" "$boundaries_file" | sort -u > "$expected_files"

    local actual_count
    actual_count=$(awk -F: '{ total += $NF } END { print total + 0 }' "$matches_file")
    if [[ "$actual_count" != "$expected_count" ]]; then
      record_violation "source rule '$name' changed: expected $expected_count matches, found $actual_count; tighten the baseline when debt is removed"
    fi

    local unexpected_files stale_files
    unexpected_files=$(comm -13 "$expected_files" "$current_files")
    stale_files=$(comm -23 "$expected_files" "$current_files")
    if [[ -n "$unexpected_files" ]]; then
      record_violation "source rule '$name' has new files: $(tr '\n' ' ' <<<"$unexpected_files")"
    fi
    if [[ -n "$stale_files" ]]; then
      record_violation "source rule '$name' has stale file exceptions: $(tr '\n' ' ' <<<"$stale_files")"
    fi
  done
}

validate_exception_metadata
collect_metadata
check_package_coverage
check_dependencies
check_features
check_source_rules

if [[ -s "$violations" ]]; then
  echo "client architecture guard failed:" >&2
  sed 's/^/  - /' "$violations" >&2
  echo "See docs/architecture/capabilities.md and config/architecture-boundaries.json." >&2
  exit 1
fi

echo "client architecture guard: ok"
