#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

if [ "${AGENT_SECRET_IN_MISE:-}" != "1" ]; then
  if ! command -v mise >/dev/null 2>&1; then
    echo "format: required command not found: mise" >&2
    exit 1
  fi

  export AGENT_SECRET_IN_MISE=1
  exec mise exec -- "$0" "$@"
fi

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(go shell toml swift)
fi

go_files=()
shell_files=()
toml_files=()

collect_files() {
  go_files=()
  shell_files=()
  toml_files=()

  while IFS= read -r path; do
    go_files+=("$path")
  done < <(find "$root" -name "*.go" -not -path "*/.git/*" -not -path "*/vendor/*" | sort)

  local dir=""
  for dir in scripts approver/scripts; do
    [ -d "$dir" ] || continue
    while IFS= read -r path; do
      shell_files+=("$path")
    done < <(find "$dir" -type f -name "*.sh" | sort)
  done

  while IFS= read -r path; do
    toml_files+=("$path")
  done < <(find "$root" -name "*.toml" -not -path "*/.git/*" | sort)
}

format_go() {
  if [ ${#go_files[@]} -gt 0 ]; then
    echo "Formatting Go files..."
    gofmt -w "${go_files[@]}"
  fi
}

format_shell() {
  if [ ${#shell_files[@]} -gt 0 ]; then
    echo "Formatting shell scripts..."
    shfmt -w -i 2 -ci "${shell_files[@]}"
  fi
}

format_toml() {
  if [ ${#toml_files[@]} -gt 0 ]; then
    echo "Formatting TOML files..."
    taplo format "${toml_files[@]}"
  fi
}

format_swift() {
  echo "Formatting Swift files..."
  swiftformat approver/Sources approver/Tests
}

collect_files

target=""
for target in "${targets[@]}"; do
  case "$target" in
    go)
      format_go
      ;;
    shell)
      format_shell
      ;;
    toml)
      format_toml
      ;;
    swift)
      format_swift
      ;;
    all)
      format_go
      format_shell
      format_toml
      format_swift
      ;;
    *)
      echo "format: unknown target: $target" >&2
      echo "Usage: scripts/format.sh [go] [shell] [toml] [swift]" >&2
      exit 2
      ;;
  esac
done

echo "format: ok"
