#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
publish_script="$project_root/scripts/publish-draft-release.sh"
workflow="$project_root/.github/workflows/ci.yml"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-publish-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-release-publish: $*" >&2
  exit 1
}

expect_log() {
  local want="$1"

  if ! grep -F -- "$want" "$tmp_dir/gh.log" >/dev/null; then
    fail "gh log did not contain $want: $(cat "$tmp_dir/gh.log")"
  fi
}

expect_failure() {
  local want="$1"
  shift

  : >"$tmp_dir/gh.log"
  if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
    fail "expected failure containing $want"
  fi
  if ! grep -F -- "$want" "$tmp_dir/stderr" >/dev/null; then
    fail "stderr did not contain $want: $(cat "$tmp_dir/stderr")"
  fi
}

stub_dir="$tmp_dir/bin"
mkdir -p "$stub_dir"
cat >"$stub_dir/gh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"$GH_STUB_LOG"

if [ "${1:-}" != "release" ]; then
  echo "unexpected gh command: $*" >&2
  exit 2
fi

case "${2:-}" in
  view)
    case "${GH_STUB_RELEASE_STATE:-missing}" in
      missing)
        exit 1
        ;;
      draft)
        if [ "${4:-}" = "--json" ]; then
          printf 'true\n'
        fi
        ;;
      published)
        if [ "${4:-}" = "--json" ]; then
          printf 'false\n'
        fi
        ;;
      *)
        echo "unknown GH_STUB_RELEASE_STATE=$GH_STUB_RELEASE_STATE" >&2
        exit 2
        ;;
    esac
    ;;
  upload | create)
    ;;
  *)
    echo "unexpected gh release command: $*" >&2
    exit 2
    ;;
esac
BASH
chmod +x "$stub_dir/gh"

artifact_arm="$tmp_dir/Agent-Secret-v1.0.0-macos-arm64.dmg"
artifact_intel="$tmp_dir/Agent-Secret-v1.0.0-macos-x86_64.dmg"
checksums="$tmp_dir/checksums.txt"
notes_file="$tmp_dir/release-notes.md"
touch "$artifact_arm" "$artifact_intel" "$checksums"
printf 'Release notes from changelog.\n' >"$notes_file"

run_publish() {
  local state="$1"

  GH_STUB_LOG="$tmp_dir/gh.log" \
    GH_STUB_RELEASE_STATE="$state" \
    AGENT_SECRET_RELEASE_NOTES_FILE="$notes_file" \
    GITHUB_SHA=abc123 \
    PATH="$stub_dir:$PATH" \
    "$publish_script" v1.0.0 "$artifact_arm" "$artifact_intel" "$checksums"
}

: >"$tmp_dir/gh.log"
run_publish missing
expect_log "release view v1.0.0"
expect_log "release create v1.0.0 $artifact_arm $artifact_intel $checksums --draft --verify-tag --title v1.0.0 --notes-file $notes_file"

: >"$tmp_dir/gh.log"
run_publish draft
expect_log "release view v1.0.0 --json isDraft --jq .isDraft"
expect_log "release upload v1.0.0 $artifact_arm $artifact_intel $checksums --clobber"

expect_failure "release v1.0.0 is already published; refusing to replace assets" run_publish published
if grep -F -- "release upload" "$tmp_dir/gh.log" >/dev/null; then
  fail "published release path attempted upload: $(cat "$tmp_dir/gh.log")"
fi

expect_failure "release notes file is required for tag releases" env \
  GH_STUB_LOG="$tmp_dir/gh.log" \
  GH_STUB_RELEASE_STATE=missing \
  PATH="$stub_dir:$PATH" \
  "$publish_script" v1.0.0 "$artifact_arm" "$artifact_intel" "$checksums"

if ! grep -F -- "scripts/publish-draft-release.sh" "$workflow" >/dev/null; then
  fail "workflow does not use scripts/publish-draft-release.sh"
fi
if ! grep -F -- "scripts/extract-release-notes.sh" "$workflow" >/dev/null; then
  fail "workflow does not extract changelog-backed release notes"
fi
if ! grep -F -- "AGENT_SECRET_RELEASE_NOTES_FILE" "$workflow" >/dev/null; then
  fail "workflow does not pass release notes file to publisher"
fi
if grep -F -- "--clobber" "$workflow" >/dev/null; then
  fail "workflow contains inline --clobber instead of the draft-state guard script"
fi

echo "test-release-publish: ok"
