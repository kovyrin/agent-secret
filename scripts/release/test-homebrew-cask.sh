#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
check_script="$project_root/scripts/release/check-homebrew-cask.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-homebrew-cask-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-homebrew-cask: $*" >&2
  exit 1
}

expect_failure() {
  local want="$1"
  shift

  if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
    fail "expected failure containing $want"
  fi
  if ! grep -F -- "$want" "$tmp_dir/stderr" >/dev/null; then
    fail "stderr did not contain $want: $(cat "$tmp_dir/stderr")"
  fi
}

cask="$tmp_dir/agent-secret.rb"
checksums="$tmp_dir/checksums.txt"
good_sha="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
bad_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

write_cask() {
  local version="$1"
  local sha256="$2"

  cat >"$cask" <<EOF
cask "agent-secret" do
  version "$version"
  sha256 "$sha256"
end
EOF
}

write_cask "1.2.3" "$good_sha"
printf '%s  Agent-Secret-v1.2.3-macos-arm64.dmg\n' "$good_sha" >"$checksums"

"$check_script" v1.2.3 "$cask" "$checksums" >"$tmp_dir/stdout"
if ! grep -F -- "check-homebrew-cask: ok" "$tmp_dir/stdout" >/dev/null; then
  fail "successful check did not print ok"
fi

write_cask "1.2.2" "$good_sha"
expect_failure "cask version is 1.2.2, expected 1.2.3" \
  "$check_script" v1.2.3 "$cask" "$checksums"

write_cask "1.2.3" "$bad_sha"
expect_failure "cask sha256 is $bad_sha, expected $good_sha" \
  "$check_script" v1.2.3 "$cask" "$checksums"

write_cask "1.2.3" "$good_sha"
printf '%s  Agent-Secret-v9.9.9-macos-arm64.dmg\n' "$good_sha" >"$checksums"
expect_failure "missing checksum for Agent-Secret-v1.2.3-macos-arm64.dmg" \
  "$check_script" v1.2.3 "$cask" "$checksums"

expect_failure "release tag must be vX.Y.Z" \
  "$check_script" 1.2.3 "$cask" "$checksums"

echo "test-homebrew-cask: ok"
