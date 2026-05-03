#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
check_script="$project_root/scripts/check-workflow-actions-pinned.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-workflow-pinning-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-workflow-actions-pinned: $*" >&2
  exit 1
}

expect_failure() {
  local want="$1"
  shift

  if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
    fail "expected failure containing $want"
  fi
  if ! grep -F "$want" "$tmp_dir/stderr" >/dev/null; then
    fail "stderr did not contain $want: $(cat "$tmp_dir/stderr")"
  fi
}

cat >"$tmp_dir/pinned.yml" <<'YAML'
name: pinned
on: push
jobs:
  pinned:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5
      - uses: ./.github/actions/local-action
YAML
"$check_script" "$tmp_dir/pinned.yml"

cat >"$tmp_dir/floating.yml" <<'YAML'
name: floating
on: push
jobs:
  floating:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
YAML
expect_failure "actions/checkout@v4" "$check_script" "$tmp_dir/floating.yml"

cat >"$tmp_dir/no-ref.yml" <<'YAML'
name: no-ref
on: push
jobs:
  no-ref:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout
YAML
expect_failure "actions/checkout" "$check_script" "$tmp_dir/no-ref.yml"

cat >"$tmp_dir/short-sha.yml" <<'YAML'
name: short-sha
on: push
jobs:
  short-sha:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@34e1148
YAML
expect_failure "actions/checkout@34e1148" "$check_script" "$tmp_dir/short-sha.yml"

echo "test-workflow-actions-pinned: ok"
