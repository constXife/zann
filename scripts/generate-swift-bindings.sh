#!/usr/bin/env bash
# Builds the zann-ffi cdylib for the macOS host and generates its Swift
# bindings into <out-dir> (library mode: the interface is read from the built
# library, so the bindings always match the exported Rust surface).
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <out-dir>" >&2
  exit 2
fi
out_dir=$1

if [[ "$(uname -s)" != Darwin ]]; then
  echo "Swift bindings are generated on macOS, got $(uname -s)" >&2
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

target_dir=$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')

cargo build -p zann-ffi --lib --locked
mkdir -p "$out_dir"
cargo run -p zann-ffi --features bindgen --bin uniffi-bindgen --locked -- \
  generate --library "$target_dir/debug/libzann_ffi.dylib" \
  --language swift --no-format --out-dir "$out_dir"
