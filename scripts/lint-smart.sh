#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

if [ "${AGENT_SECRET_IN_MISE:-}" != "1" ]; then
  if ! command -v mise >/dev/null 2>&1; then
    echo "lint-smart: required command not found: mise" >&2
    exit 1
  fi

  export AGENT_SECRET_IN_MISE=1
  exec mise exec -- "$0" "$@"
fi

mode="${1:---staged}"
case "$mode" in
  --staged)
    use_staged=1
    ;;
  --worktree)
    use_staged=0
    ;;
  -h | --help)
    cat <<'USAGE'
Usage:
  scripts/lint-smart.sh [--staged | --worktree]

Runs lint checks only for changed files. Pre-commit uses --staged.
USAGE
    exit 0
    ;;
  *)
    echo "lint-smart: unknown argument: $mode" >&2
    exit 2
    ;;
esac

changed_files=()
if [ "$use_staged" -eq 1 ]; then
  while IFS= read -r -d '' file; do
    changed_files+=("$file")
  done < <(git diff --cached --name-only -z --diff-filter=ACMRT)
else
  while IFS= read -r -d '' file; do
    changed_files+=("$file")
  done < <(git diff --name-only -z --diff-filter=ACMRT)

  while IFS= read -r -d '' file; do
    changed_files+=("$file")
  done < <(git ls-files --others --exclude-standard -z)
fi

if [ ${#changed_files[@]} -eq 0 ]; then
  echo "lint-smart: no changed files"
  exit 0
fi

go_files=()
go_targets=()
go_config_changed=0
markdown_files=()
shell_files=()
swift_files=()
workflow_files=()
npm_changed=0
mise_changed=0
markdown_config_changed=0
swiftlint_config_changed=0

add_unique() {
  local item="$1"
  shift

  local existing=""
  for existing in "$@"; do
    if [ "$existing" = "$item" ]; then
      return 1
    fi
  done

  return 0
}

add_go_target() {
  local target="$1"

  if [ ${#go_targets[@]} -eq 0 ]; then
    go_targets+=("$target")
  elif add_unique "$target" "${go_targets[@]}"; then
    go_targets+=("$target")
  fi
}

nearest_go_mod_dir() {
  local file_dir="$1"
  local dir="$root/$file_dir"

  while true; do
    if [ -f "$dir/go.mod" ]; then
      printf '%s\n' "$dir"
      return 0
    fi

    if [ "$dir" = "$root" ] || [ "$dir" = "/" ]; then
      return 1
    fi

    dir="$(dirname "$dir")"
  done
}

add_go_target_for_file() {
  local file="$1"
  local file_dir=""
  file_dir="$(dirname "$file")"

  local module_dir=""
  if ! module_dir="$(nearest_go_mod_dir "$file_dir")"; then
    echo "lint-smart: no go.mod found for $file" >&2
    exit 1
  fi

  case "$(basename "$file")" in
    go.mod | go.sum)
      add_go_target "$module_dir::./..."
      ;;
    *)
      local abs_file_dir="$root/$file_dir"
      local package_dir="${abs_file_dir#"$module_dir"}"
      package_dir="${package_dir#/}"
      if [ -z "$package_dir" ]; then
        add_go_target "$module_dir::."
      else
        add_go_target "$module_dir::./$package_dir"
      fi
      ;;
  esac
}

for file in "${changed_files[@]}"; do
  [ -f "$file" ] || continue

  case "$file" in
    *.go)
      go_files+=("$file")
      add_go_target_for_file "$file"
      ;;
    go.mod | go.sum | */go.mod | */go.sum)
      add_go_target_for_file "$file"
      ;;
    .golangci.yml)
      go_config_changed=1
      ;;
    *.md)
      markdown_files+=("$file")
      ;;
    *.swift)
      swift_files+=("$file")
      ;;
    package.json | package-lock.json)
      npm_changed=1
      markdown_config_changed=1
      ;;
    mise.toml)
      mise_changed=1
      ;;
    .swiftlint.yml)
      swiftlint_config_changed=1
      ;;
    .markdownlintignore)
      markdown_config_changed=1
      ;;
    .github/workflows/*.yml | .github/workflows/*.yaml)
      workflow_files+=("$file")
      ;;
  esac

  if [[ "$file" == *.sh ]]; then
    shell_files+=("$file")
  elif IFS= read -r first_line <"$file"; then
    case "$first_line" in
      '#!'*'/sh' | '#!'*'/bash' | '#!'*'/zsh' | '#!'*'env sh' | '#!'*'env bash' | '#!'*'env zsh')
        shell_files+=("$file")
        ;;
    esac
  fi
done

if [ "$mise_changed" -eq 1 ]; then
  echo "Running mise install..."
  mise install
fi

if [ "$npm_changed" -eq 1 ]; then
  echo "Verifying npm lock install..."
  npm ci --ignore-scripts --no-audit --no-fund
fi

echo "Running gitleaks on changed content..."
if [ "$use_staged" -eq 1 ]; then
  gitleaks git --staged --redact --no-banner
else
  gitleaks dir . --redact --no-banner
fi

if [ ${#go_files[@]} -gt 0 ]; then
  echo "Running gofmt on changed Go files..."
  gofmt_out="$(gofmt -l "${go_files[@]}")"
  if [ -n "$gofmt_out" ]; then
    echo "gofmt required on:"
    echo "$gofmt_out"
    exit 1
  fi
fi

if [ ${#go_targets[@]} -gt 0 ]; then
  target=""
  for target in "${go_targets[@]}"; do
    module_dir="${target%%::*}"
    package_pattern="${target#*::}"
    echo "Running go vet: $module_dir $package_pattern"
    (cd "$module_dir" && go vet "$package_pattern")
  done
fi

if [ "$go_config_changed" -eq 1 ]; then
  echo "Running golangci-lint on all Go files..."
  golangci-lint run --timeout 5m
elif [ ${#go_targets[@]} -gt 0 ]; then
  target=""
  for target in "${go_targets[@]}"; do
    module_dir="${target%%::*}"
    package_pattern="${target#*::}"
    echo "Running golangci-lint: $module_dir $package_pattern"
    (cd "$module_dir" && golangci-lint run --timeout 5m "$package_pattern")
  done
fi

if [ ${#shell_files[@]} -gt 0 ]; then
  echo "Running shellcheck on changed shell files..."
  shellcheck "${shell_files[@]}"
fi

if [ ${#workflow_files[@]} -gt 0 ]; then
  echo "Running actionlint on changed workflows..."
  actionlint "${workflow_files[@]}"
fi

if [ "$swiftlint_config_changed" -eq 1 ]; then
  echo "Running SwiftLint on all Swift files..."
  swiftlint lint --strict --no-cache
elif [ ${#swift_files[@]} -gt 0 ]; then
  echo "Running SwiftLint on changed Swift files..."
  swiftlint lint --strict --no-cache --force-exclude "${swift_files[@]}"
fi

if [ ${#markdown_files[@]} -gt 0 ] || [ "$markdown_config_changed" -eq 1 ]; then
  if [ ! -x node_modules/.bin/markdownlint ]; then
    npm ci --ignore-scripts --no-audit --no-fund
  fi

  if [ "$markdown_config_changed" -eq 1 ]; then
    echo "Running markdownlint on all Markdown files..."
    npx --no-install markdownlint '**/*.md'
  else
    echo "Running markdownlint on changed Markdown files..."
    npx --no-install markdownlint "${markdown_files[@]}"
  fi
fi

echo "lint-smart: ok"
