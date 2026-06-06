#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$root"

default_min_package="${AGENT_SECRET_GO_COVERAGE_MIN_PACKAGE:-80}"
min_total="${AGENT_SECRET_GO_COVERAGE_MIN_TOTAL:-77}"
test_parallelism="${AGENT_SECRET_GO_COVERAGE_TEST_PARALLELISM:-1}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

coverage_profile="$tmp_dir/coverage.out"
test_output="$tmp_dir/go-test.out"

packages=()
while IFS= read -r package; do
  case "$package" in
    */internal/testsupport/*)
      ;;
    *)
      packages+=("$package")
      ;;
  esac
done < <(go list ./internal/...)
if [ "${#packages[@]}" -eq 0 ]; then
  echo "coverage: no internal Go packages found" >&2
  exit 1
fi

echo "Running fresh Go coverage gate: explicit package floors, total >= ${min_total}%"
go test -count=1 -p="$test_parallelism" -covermode=atomic -coverprofile="$coverage_profile" "${packages[@]}" | tee "$test_output"

is_less_than() {
  local value="$1"
  local minimum="$2"

  awk -v value="$value" -v minimum="$minimum" \
    'BEGIN { exit !((value + 0) < (minimum + 0)) }'
}

failures=0
coverage_lines=0

package_floor() {
  local package_name="$1"

  case "$package_name" in
    github.com/kovyrin/agent-secret/internal/daemon/approval) printf '%s\n' "40" ;;
    github.com/kovyrin/agent-secret/internal/daemon/peertrust) printf '%s\n' "70" ;;
    github.com/kovyrin/agent-secret/internal/daemon/process) printf '%s\n' "45" ;;
    github.com/kovyrin/agent-secret/internal/daemon/protocol) printf '%s\n' "65" ;;
    github.com/kovyrin/agent-secret/internal/daemon/socket) printf '%s\n' "75" ;;
    github.com/kovyrin/agent-secret/internal/daemon/trust) printf '%s\n' "1" ;;
    # Includes Darwin Security.framework wrappers that are covered by live Keychain smoke tests, not unit tests.
    github.com/kovyrin/agent-secret/internal/bwsm) printf '%s\n' "60" ;;
    github.com/kovyrin/agent-secret/internal/opresolver) printf '%s\n' "75" ;;
    github.com/kovyrin/agent-secret/internal/policy) printf '%s\n' "75" ;;
    github.com/kovyrin/agent-secret/internal/profileconfig) printf '%s\n' "85" ;;
    github.com/kovyrin/agent-secret/internal/randid) printf '%s\n' "95" ;;
    github.com/kovyrin/agent-secret/internal/request) printf '%s\n' "85" ;;
    github.com/kovyrin/agent-secret/internal/secretcache) printf '%s\n' "90" ;;
    *) printf '%s\n' "$default_min_package" ;;
  esac
}

while IFS= read -r line; do
  case "$line" in
    *"coverage:"*)
      coverage_lines=$((coverage_lines + 1))
      read -r -a line_fields <<<"$line"
      if [ "${line_fields[0]:-}" = "ok" ]; then
        package_name="${line_fields[1]:-}"
      else
        package_name="${line_fields[0]:-}"
      fi
      if [ -z "$package_name" ]; then
        echo "coverage: could not parse package from go test line: $line" >&2
        failures=$((failures + 1))
        continue
      fi
      percent="$(printf '%s\n' "$line" | sed -E 's/.*coverage: ([0-9.]+)%.*/\1/')"
      minimum="$(package_floor "$package_name")"
      if is_less_than "$percent" "$minimum"; then
        echo "coverage: ${package_name} is ${percent}%, below package floor ${minimum}%" >&2
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
