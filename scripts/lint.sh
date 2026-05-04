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
go test -race ./...
scripts/checks/check-go-coverage.sh
govulncheck ./...
gitleaks dir . --redact --no-banner

if [ ! -x node_modules/.bin/markdownlint ]; then
  npm ci --ignore-scripts --no-audit --no-fund
fi

shell_files=(install.sh uninstall.sh)
while IFS= read -r -d '' file; do
  shell_files+=("$file")
done < <(find scripts approver/scripts -type f -name "*.sh" -print0 | sort -z)
shellcheck "${shell_files[@]}"
scripts/checks/check-format.sh shell
if [ -d .github/workflows ]; then
  workflow_files=()
  while IFS= read -r -d '' file; do
    workflow_files+=("$file")
  done < <(find .github/workflows -type f \( -name "*.yml" -o -name "*.yaml" \) -print0)

  if [ ${#workflow_files[@]} -gt 0 ]; then
    actionlint "${workflow_files[@]}"
    scripts/checks/check-workflow-actions-pinned.sh "${workflow_files[@]}"
  fi
fi
scripts/checks/check-format.sh toml
scripts/checks/check-format.sh swift
swiftlint lint --strict --no-cache
npx --no-install markdownlint '**/*.md'

scripts/checks/test-workflow-actions-pinned.sh

(cd approver && swift test)
