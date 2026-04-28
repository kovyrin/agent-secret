#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

if [ "${AGENT_SECRET_IN_MISE:-}" != "1" ]; then
  if ! command -v mise >/dev/null 2>&1; then
    echo "lint: required command not found: mise" >&2
    exit 1
  fi

  export AGENT_SECRET_IN_MISE=1
  exec mise exec -- "$0" "$@"
fi

scripts/lint-go.sh
go test ./...

if [ ! -x node_modules/.bin/markdownlint ]; then
  npm ci --ignore-scripts --no-audit --no-fund
fi

shellcheck scripts/*.sh approver/scripts/*.sh
if [ -d .github/workflows ]; then
  workflow_files=()
  while IFS= read -r -d '' file; do
    workflow_files+=("$file")
  done < <(find .github/workflows -type f \( -name "*.yml" -o -name "*.yaml" \) -print0)

  if [ ${#workflow_files[@]} -gt 0 ]; then
    actionlint "${workflow_files[@]}"
  fi
fi
swiftlint lint --strict --no-cache
npx --no-install markdownlint '**/*.md'

(cd approver && swift test)
