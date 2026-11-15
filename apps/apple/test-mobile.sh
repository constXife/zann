#!/usr/bin/env bash
# Run real app/unit/UI tests on one iPhone and iPad mini (A17 Pro) from the newest
# installed iOS runtime. Missing runtimes/device families are hard errors.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

inventory=$(xcrun simctl list --json)
destinations=$(python3 -c '
import json, subprocess, sys
inventory = json.load(sys.stdin)
runtimes = [r for r in inventory["runtimes"]
            if r["isAvailable"] and r["identifier"].startswith("com.apple.CoreSimulator.SimRuntime.iOS-")]
if not runtimes:
    sys.exit("No installed iOS Simulator runtime; install one through Xcode Components.")
runtime = max(runtimes, key=lambda r: tuple(map(int, r["version"].split("."))))
families = {d["identifier"]: d["productFamily"] for d in inventory["devicetypes"]}
devices = inventory["devices"][runtime["identifier"]]
for family in ("iPhone", "iPad"):
    candidates = [d for d in devices if d["isAvailable"] and families[d["deviceTypeIdentifier"]] == family]
    if family == "iPad":
        mini_type = "com.apple.CoreSimulator.SimDeviceType.iPad-mini-A17-Pro"
        candidates = [d for d in candidates if d["deviceTypeIdentifier"] == mini_type]
        if not candidates:
            identifier = subprocess.check_output([
                "xcrun", "simctl", "create", "Zann iPad mini", mini_type, runtime["identifier"]
            ], text=True).strip()
            print("platform=iOS Simulator,id=" + identifier)
            continue
    if not candidates:
        sys.exit("No available " + family + " in " + runtime["name"])
    device = min(candidates, key=lambda d: (d["name"], d["udid"]))
    print("platform=iOS Simulator,id=" + device["udid"])
' <<< "$inventory")

# One xcodebuild invocation per device keeps scheduling and xcresult ownership
# separate. Xcode's multi-destination mode can leave the next worker queued and
# retain only the first destination in the completed result bundle.
mkdir -p build/mobile/Logs/Test
while IFS= read -r destination; do
  result_bundle="build/mobile/Logs/Test/Mobile-$(uuidgen).xcresult"
  if xcodebuild test -quiet -project Zann.xcodeproj -scheme ZannMobile \
    -derivedDataPath build/mobile -parallel-testing-enabled NO \
    -destination "$destination" -resultBundlePath "$result_bundle"; then
    continue
  else
    test_status=$?
  fi
  # Keep the original Xcode failure, with assertion locations in the CI log.
  if summary=$(xcrun xcresulttool get test-results summary --path "$result_bundle"); then
    printf '%s\n' "$summary"
    if failures=$(python3 -c '
import json, sys
for failure in json.load(sys.stdin)["testFailures"]:
    print(failure["testIdentifierString"])
' <<< "$summary"); then
      while IFS= read -r test_id; do
        [[ -n "$test_id" ]] || continue
        if ! xcrun xcresulttool get test-results test-details --path "$result_bundle" --test-id "$test_id"; then
          printf 'Could not read failure details for %s\n' "$test_id" >&2
        fi
      done <<< "$failures"
    fi
  fi
  exit "$test_status"
done <<< "$destinations"
