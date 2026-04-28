#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

git config core.hooksPath .githooks
echo "Configured git hooks path: .githooks"
