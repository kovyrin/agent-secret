#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

go_tool=(go)
if ! command -v go >/dev/null 2>&1; then
  if command -v mise >/dev/null 2>&1; then
    go_tool=(mise x go@1.26.2 -- go)
  else
    echo "lint: required command not found: go" >&2
    exit 1
  fi
fi

scripts/lint-go.sh
"${go_tool[@]}" test ./...

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck scripts/*.sh approver/scripts/*.sh
else
  echo "lint: shellcheck not found; skipping shell lint" >&2
fi

if command -v npx >/dev/null 2>&1; then
  npx --yes markdownlint-cli '**/*.md'
else
  echo "lint: npx not found; skipping markdownlint" >&2
fi

(cd approver && swift test)
