#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export K6_SCENARIO="${K6_SCENARIO:-baseline_normal}"
export K6_PROFILE="${K6_PROFILE:-normal}"

if [ "$#" -eq 0 ]; then
  set -- run "${script_dir}/k6/runner.js"
fi

exec "${script_dir}/run_scenario.sh" "$@"
