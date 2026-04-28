#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

go_tool=(go)
gofmt_tool=(gofmt)
if ! command -v go >/dev/null 2>&1; then
  if command -v mise >/dev/null 2>&1; then
    go_tool=(mise x go@1.26.2 -- go)
    gofmt_tool=(mise x go@1.26.2 -- gofmt)
  else
    echo "lint-go: required command not found: go" >&2
    exit 1
  fi
fi

modules=()
while IFS= read -r path; do
  case "$path" in
    */vendor/*)
      continue
      ;;
  esac
  modules+=("$path")
done < <(find "$root" -name go.mod -not -path "*/.git/*")

if [ ${#modules[@]} -eq 0 ]; then
  echo "lint-go: no Go modules found"
  exit 0
fi

for mod in "${modules[@]}"; do
  module_dir="$(dirname "$mod")"
  echo "Linting Go module: $module_dir"

  go_files=()
  while IFS= read -r path; do
    go_files+=("$path")
  done < <(find "$module_dir" -name "*.go" -not -path "*/vendor/*")

  if [ ${#go_files[@]} -gt 0 ]; then
    gofmt_out="$("${gofmt_tool[@]}" -l "${go_files[@]}")"
    if [ -n "$gofmt_out" ]; then
      echo "gofmt required on:"
      echo "$gofmt_out"
      exit 1
    fi
  fi

  (cd "$module_dir" && "${go_tool[@]}" vet ./...)
done
