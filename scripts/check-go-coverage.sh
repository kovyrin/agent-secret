#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

min_package="${AGENT_SECRET_GO_COVERAGE_MIN_PACKAGE:-55}"
min_total="${AGENT_SECRET_GO_COVERAGE_MIN_TOTAL:-65}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

coverage_profile="$tmp_dir/coverage.out"
test_output="$tmp_dir/go-test.out"

packages=()
while IFS= read -r package; do
  packages+=("$package")
done < <(go list ./internal/...)
if [ "${#packages[@]}" -eq 0 ]; then
  echo "coverage: no internal Go packages found" >&2
  exit 1
fi

echo "Running Go coverage gate: package >= ${min_package}%, total >= ${min_total}%"
go test -covermode=atomic -coverprofile="$coverage_profile" "${packages[@]}" | tee "$test_output"

is_less_than() {
  local value="$1"
  local minimum="$2"

  awk -v value="$value" -v minimum="$minimum" \
    'BEGIN { exit !((value + 0) < (minimum + 0)) }'
}

failures=0
coverage_lines=0

while read -r _status package_name rest; do
  case "$rest" in
    *"coverage:"*)
      coverage_lines=$((coverage_lines + 1))
      percent="$(printf '%s\n' "$rest" | sed -E 's/.*coverage: ([0-9.]+)%.*/\1/')"
      if is_less_than "$percent" "$min_package"; then
        echo "coverage: ${package_name} is ${percent}%, below package floor ${min_package}%" >&2
        failures=$((failures + 1))
      fi
      ;;
  esac
done <"$test_output"

if [ "$coverage_lines" -eq 0 ]; then
  echo "coverage: go test output did not contain package coverage lines" >&2
  exit 1
fi

total_percent="$(go tool cover -func="$coverage_profile" | awk '/^total:/ { gsub("%", "", $3); print $3 }')"
if [ -z "$total_percent" ]; then
  echo "coverage: could not read total coverage from profile" >&2
  exit 1
fi

if is_less_than "$total_percent" "$min_total"; then
  echo "coverage: total is ${total_percent}%, below total floor ${min_total}%" >&2
  failures=$((failures + 1))
fi

if [ "$failures" -gt 0 ]; then
  exit 1
fi

echo "coverage: ok, total ${total_percent}%"
