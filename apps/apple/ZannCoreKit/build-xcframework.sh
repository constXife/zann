#!/usr/bin/env bash
# Builds the arm64 macOS slice by default; --all-platforms adds iOS and its
# simulator. Packs Generated/ZannFFI.xcframework and generates Generated/Swift.
# Deployment targets come from Package.swift.
set -euo pipefail

usage() {
  echo "usage: $0 <debug|release> [--all-platforms]"
}
if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# -lt 1 || $# -gt 2 || ( $1 != debug && $1 != release ) ]]; then
  usage >&2
  exit 2
fi
profile=$1
targets=(aarch64-apple-darwin)
sdks=(macosx)
if [[ $# -eq 2 ]]; then
  if [[ $2 != --all-platforms ]]; then
    usage >&2
    exit 2
  fi
  targets+=(aarch64-apple-ios aarch64-apple-ios-sim)
  sdks+=(iphoneos iphonesimulator)
fi

package_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$package_dir/../../.." && pwd)
generated="$package_dir/Generated"
cd "$repo_root"

if [[ $(uname -s) != Darwin ]]; then
  echo "error: build on macOS with full Xcode selected (xcode-select --switch /Applications/Xcode.app/Contents/Developer)" >&2
  exit 1
fi
for tool in cargo rustup jq swift xcrun xcodebuild; do
  if ! command -v "$tool" >/dev/null; then
    echo "error: missing $tool; see apps/apple/README.md prerequisites (brew install jq; install Rust via rustup and full Xcode)" >&2
    exit 1
  fi
done

installed_targets=$(rustup target list --installed)
for target in "${targets[@]}"; do
  if ! grep -Fxq "$target" <<<"$installed_targets"; then
    echo "error: missing Rust target $target; run: rustup target add ${targets[*]}" >&2
    exit 1
  fi
done
for sdk in "${sdks[@]}"; do
  if ! xcrun --sdk "$sdk" --show-sdk-path >/dev/null; then
    echo "error: $sdk SDK unavailable; select full Xcode and install the requested platform in Xcode Settings > Components" >&2
    exit 1
  fi
done

# Cargo's `dev` profile writes to target/<triple>/debug.
cargo_profile=dev
if [[ $profile == release ]]; then
  cargo_profile=release
fi

platform_version() {
  jq -er --arg name "$1" '.platforms[] | select(.platformName == $name) | .version' \
    <<<"$package_json"
}
package_json=$(swift package dump-package --package-path "$package_dir")
export MACOSX_DEPLOYMENT_TARGET
MACOSX_DEPLOYMENT_TARGET=$(platform_version macos)
if [[ ${#targets[@]} -gt 1 ]]; then
  export IPHONEOS_DEPLOYMENT_TARGET
  IPHONEOS_DEPLOYMENT_TARGET=$(platform_version ios)
fi

target_dir=$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')

cargo_args=(-p zann-ffi --lib --locked --profile "$cargo_profile")
if [[ $profile == debug ]]; then
  cargo_args+=(--features test-support)
fi

for target in "${targets[@]}"; do
  cargo rustc "${cargo_args[@]}" --target "$target" --crate-type staticlib
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
