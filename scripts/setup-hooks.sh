#!/usr/bin/env bash
set -euo pipefail

git config core.hooksPath scripts/hooks
echo "Git hooks path set to scripts/hooks"
