#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
extract_script="$project_root/scripts/extract-release-notes.sh"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-notes-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-release-notes: $*" >&2
  exit 1
}

expect_failure() {
  local name="$1"
  local want="$2"
  shift 2

  if "$@" >"$tmp_dir/$name.stdout" 2>"$tmp_dir/$name.stderr"; then
    fail "$name succeeded unexpectedly"
  fi
  if ! grep -F -- "$want" "$tmp_dir/$name.stderr" >/dev/null; then
    fail "$name stderr did not contain $want: $(cat "$tmp_dir/$name.stderr")"
  fi
}

write_changelog() {
  local path="$1"
  local section="$2"

  cat >"$path" <<EOF
# Changelog

$section

## [0.9.0] - 2026-01-01

- Older release.
EOF
}

missing="$tmp_dir/missing.md"
write_changelog "$missing" "## [1.1.0] - 2026-01-01

- Different release."
expect_failure missing "missing changelog section for v1.0.0" \
  "$extract_script" v1.0.0 "$tmp_dir/missing-notes.md" "$missing"

expect_failure invalid_tag "release tag must be vX.Y.Z" \
  "$extract_script" v1.0.0-beta "$tmp_dir/invalid-tag-notes.md" "$missing"

pending="$tmp_dir/pending.md"
write_changelog "$pending" "## [1.0.0] - Pending

- Release entry."
expect_failure pending "changelog section for v1.0.0 is still Pending" \
  "$extract_script" v1.0.0 "$tmp_dir/pending-notes.md" "$pending"

empty="$tmp_dir/empty.md"
write_changelog "$empty" "## [1.0.0] - 2026-05-03"
expect_failure empty "changelog section for v1.0.0 is empty" \
  "$extract_script" v1.0.0 "$tmp_dir/empty-notes.md" "$empty"

valid="$tmp_dir/valid.md"
write_changelog "$valid" "## [1.0.0] - 2026-05-03

### Security

- Require changelog-backed release notes."
notes="$tmp_dir/release-notes.md"
"$extract_script" v1.0.0 "$notes" "$valid"

if ! grep -F -- "## [1.0.0] - 2026-05-03" "$notes" >/dev/null; then
  fail "valid notes did not include release heading: $(cat "$notes")"
fi
if ! grep -F -- "Require changelog-backed release notes." "$notes" >/dev/null; then
  fail "valid notes did not include release body: $(cat "$notes")"
fi
if grep -F -- "Older release." "$notes" >/dev/null; then
  fail "valid notes included following release section: $(cat "$notes")"
fi

echo "test-release-notes: ok"
