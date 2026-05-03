#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
check_script="$project_root/scripts/check-release-ancestry.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-ancestry-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-release-ancestry: $*" >&2
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

origin="$tmp_dir/origin.git"
repo="$tmp_dir/repo"

git init --bare "$origin" >/dev/null
git init "$repo" >/dev/null
git -C "$repo" config user.email agent-secret@example.invalid
git -C "$repo" config user.name "Agent Secret Test"
git -C "$repo" remote add origin "$origin"

printf 'base\n' >"$repo/file.txt"
git -C "$repo" add file.txt
git -C "$repo" commit -m "base" >/dev/null
git -C "$repo" branch -M main
git -C "$repo" push -u origin main >/dev/null

git -C "$repo" tag v1.0.0
(
  cd "$repo"
  "$check_script" v1.0.0 >/dev/null
)

printf 'reviewed\n' >>"$repo/file.txt"
git -C "$repo" commit -am "reviewed" >/dev/null
git -C "$repo" push origin main >/dev/null
git -C "$repo" tag -a v1.0.1 -m "v1.0.1"
(
  cd "$repo"
  "$check_script" refs/tags/v1.0.1 >/dev/null
)

expect_failure "tag v1.0.0 targets stale commit" bash -c "cd '$repo' && '$check_script' v1.0.0"

git -C "$repo" switch -c unreviewed >/dev/null
printf 'unreviewed\n' >>"$repo/file.txt"
git -C "$repo" commit -am "unreviewed" >/dev/null
git -C "$repo" tag v1.0.2
expect_failure "tag v1.0.2 targets commit" bash -c "cd '$repo' && '$check_script' v1.0.2"

expect_failure "release ref must be a v* tag" bash -c "cd '$repo' && '$check_script' main"

echo "test-release-ancestry: ok"
