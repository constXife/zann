#!/usr/bin/env bash
# Builds libzann_ffi.a for macOS, iOS and the iOS simulator (arm64), packs the
# slices into Generated/ZannFFI.xcframework and generates the Swift bindings
# into Generated/Swift. Deployment targets come from Package.swift.
set -euo pipefail

if [[ $# -ne 1 || ( $1 != debug && $1 != release ) ]]; then
  echo "usage: $0 <debug|release>" >&2
  exit 2
fi
profile=$1
# Cargo's `dev` profile writes to target/<triple>/debug.
cargo_profile=dev
if [[ $profile == release ]]; then
  cargo_profile=release
fi

package_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$package_dir/../../.." && pwd)
generated="$package_dir/Generated"

platform_version() {
  jq -er --arg name "$1" '.platforms[] | select(.platformName == $name) | .version' \
    <<<"$package_json"
}
package_json=$(swift package dump-package --package-path "$package_dir")
export MACOSX_DEPLOYMENT_TARGET
export IPHONEOS_DEPLOYMENT_TARGET
MACOSX_DEPLOYMENT_TARGET=$(platform_version macos)
IPHONEOS_DEPLOYMENT_TARGET=$(platform_version ios)

cd "$repo_root"
target_dir=$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')

targets=(aarch64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim)
for target in "${targets[@]}"; do
  cargo rustc -p zann-ffi --lib --locked --target "$target" --profile "$cargo_profile" \
    --crate-type staticlib
done

rm -rf "$generated"
mkdir -p "$generated/Swift" "$generated/headers"
bindings=$(mktemp -d)
trap 'rm -rf "$bindings"' EXIT

# Library mode reads the exported interface from the built macOS slice.
cargo run -p zann-ffi --features bindgen --bin uniffi-bindgen --locked -- \
  generate --library "$target_dir/aarch64-apple-darwin/$profile/libzann_ffi.a" \
  --language swift --no-format --out-dir "$bindings"
mv "$bindings/zann_ffi.swift" "$generated/Swift/"
mv "$bindings/zann_ffiFFI.h" "$generated/headers/"
mv "$bindings/zann_ffiFFI.modulemap" "$generated/headers/module.modulemap"

xcframework_args=()
for target in "${targets[@]}"; do
  xcframework_args+=(-library "$target_dir/$target/$profile/libzann_ffi.a" -headers "$generated/headers")
done
xcodebuild -create-xcframework "${xcframework_args[@]}" \
  -output "$generated/ZannFFI.xcframework"
rm -rf "$generated/headers"
