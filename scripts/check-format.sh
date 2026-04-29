#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

if [ "${AGENT_SECRET_IN_MISE:-}" != "1" ]; then
  if ! command -v mise >/dev/null 2>&1; then
    echo "check-format: required command not found: mise" >&2
    exit 1
  fi

  export AGENT_SECRET_IN_MISE=1
  exec mise exec -- "$0" "$@"
fi

format_hint() {
  local formatter="$1"

  {
    echo
    echo "Formatting check failed for $formatter."
    echo "Run \`mise format\` to automatically format the repo, then stage the updated files and retry."
  } >&2
}

collect_go_files() {
  find "$root" -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" | sort
}

collect_shell_files() {
  local dir=""
  for dir in scripts approver/scripts; do
    [ -d "$dir" ] || continue
    find "$dir" -type f -name "*.sh"
  done | sort
}

collect_toml_files() {
  find "$root" -name "*.toml" -not -path "*/.git/*" | sort
}

check_go() {
  local files=("$@")
  if [ ${#files[@]} -eq 0 ]; then
    while IFS= read -r path; do
      files+=("$path")
    done < <(collect_go_files)
  fi

  [ ${#files[@]} -gt 0 ] || return 0

  local out=""
  if ! out="$(gofmt -l "${files[@]}")"; then
    printf '%s\n' "$out"
    format_hint "gofmt"
    exit 1
  fi

  if [ -n "$out" ]; then
    echo "gofmt required on:"
    printf '%s\n' "$out"
    format_hint "gofmt"
    exit 1
  fi
}

check_shell() {
  local files=("$@")
  if [ ${#files[@]} -eq 0 ]; then
    while IFS= read -r path; do
      files+=("$path")
    done < <(collect_shell_files)
  fi

  [ ${#files[@]} -gt 0 ] || return 0

  local out=""
  if ! out="$(shfmt -d -i 2 -ci "${files[@]}")"; then
    printf '%s\n' "$out"
    format_hint "shfmt"
    exit 1
  fi

  if [ -n "$out" ]; then
    printf '%s\n' "$out"
    format_hint "shfmt"
    exit 1
  fi
}

check_toml() {
  local files=("$@")
  if [ ${#files[@]} -eq 0 ]; then
    while IFS= read -r path; do
      files+=("$path")
    done < <(collect_toml_files)
  fi

  [ ${#files[@]} -gt 0 ] || return 0

  if ! taplo format --check "${files[@]}"; then
    format_hint "taplo"
    exit 1
  fi
}

check_swift() {
  local paths=("$@")
  if [ ${#paths[@]} -eq 0 ]; then
    paths=(approver/Sources approver/Tests)
  fi

  if ! swiftformat --lint --strict "${paths[@]}"; then
    format_hint "SwiftFormat"
    exit 1
  fi
}

target="${1:-all}"
if [ $# -gt 0 ]; then
  shift
fi

case "$target" in
  go)
    check_go "$@"
    ;;
  shell)
    check_shell "$@"
    ;;
  toml)
    check_toml "$@"
    ;;
  swift)
    check_swift "$@"
    ;;
  all)
    check_go
    check_shell
    check_toml
    check_swift
    ;;
  *)
    echo "check-format: unknown target: $target" >&2
    echo "Usage: scripts/check-format.sh [go|shell|toml|swift|all] [paths...]" >&2
    exit 2
    ;;
esac
