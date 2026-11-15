#!/usr/bin/env bash
set -euo pipefail

case "$CONFIGURATION" in
  Debug) expected_profile=debug ;;
  Release) expected_profile=release ;;
  *) echo "error: unsupported Apple build configuration: $CONFIGURATION" >&2; exit 1 ;;
esac

if [[ "$ZANN_CORE_BUILD_PROFILE" != "$expected_profile" ]]; then
  echo "error: rebuild ZannCoreKit with build-xcframework.sh $expected_profile before building $CONFIGURATION" >&2
  exit 1
fi
