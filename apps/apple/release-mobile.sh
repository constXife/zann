#!/usr/bin/env bash
# Prepare a signed archive and locally exported TestFlight IPA; never upload.
set -euo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [[ $# != 3 || "$1" != /* || ! "$2" =~ ^[1-9][0-9]*$ || "$3" != /* ]]; then
  echo 'Usage: release-mobile.sh ABSOLUTE_OUTPUT_DIRECTORY BUILD_NUMBER ABSOLUTE_EXPORT_OPTIONS_PLIST' >&2
  exit 2
fi
output=$1
build_number=$2
options=$3
if [[ -e "$output" || -n "$(git status --porcelain)" ]]; then
  echo 'Release requires a new output directory and a clean committed source tree.' >&2
  exit 1
fi
if [[ "$(plutil -extract method raw "$options")" != app-store-connect ||
      "$(plutil -extract destination raw "$options")" != export ]]; then
  echo 'Export options must explicitly select method=app-store-connect and destination=export.' >&2
  exit 1
fi
mkdir -m 700 "$output"
git rev-parse HEAD > "$output/source-revision.txt"
xcodebuild -version > "$output/toolchain.txt"
rustc -Vv >> "$output/toolchain.txt"
apps/apple/ZannCoreKit/build-xcframework.sh release --all-platforms
if rg -q 'seedOfflineFixture|seedOfflineStorage' apps/apple/ZannCoreKit/Generated/Swift/zann_ffi.swift; then
  echo 'Release bindings contain test fixtures.' >&2
  exit 1
fi
xcodegen --spec apps/apple/project.yml
xcodebuild archive -project apps/apple/Zann.xcodeproj -scheme ZannMobile \
  -configuration Release -destination 'generic/platform=iOS' \
  -archivePath "$output/ZannMobile.xcarchive" \
  -derivedDataPath "$output/DerivedData" CURRENT_PROJECT_VERSION="$build_number"
app="$output/ZannMobile.xcarchive/Products/Applications/ZannMobile.app"
symbols=$(xcrun nm -j "$app/ZannMobile")
if rg -q 'MobileUIFixture|MobileTestHost|MemoryKeystore|MemorySecretStore|seed_offline_fixture|seed_offline_storage' <<< "$symbols"; then
  echo 'Release archive contains test support.' >&2
  exit 1
fi
codesign --verify --deep --strict "$app"
codesign -d --entitlements :- "$app" > "$output/entitlements.plist"
cp "$options" "$output/ExportOptions.plist"
xcodebuild -exportArchive -archivePath "$output/ZannMobile.xcarchive" \
  -exportPath "$output/export" -exportOptionsPlist "$output/ExportOptions.plist"
find "$output/export" -name '*.ipa' -exec shasum -a 256 {} \; > "$output/ipa-sha256.txt"
if [[ ! -s "$output/ipa-sha256.txt" ]]; then
  echo 'Export produced no IPA.' >&2
  exit 1
fi
