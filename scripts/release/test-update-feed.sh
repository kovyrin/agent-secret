#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-promotion-test.XXXXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cd "$project_root"
go test ./scripts/release

# Rejected promotion must not contact either the public asset host or R2.
cat >"$scratch/git" <<'SH'
#!/bin/sh
case "$1" in
  status | fetch) ;;
  rev-parse) printf 'fixture-head\n' ;;
  *) exit 88 ;;
esac
SH
cat >"$scratch/gh" <<'SH'
#!/bin/sh
tag="$3"
printf '{"tagName":"%s","isDraft":%s,"isPrerelease":%s,"assets":[{"name":"Agent-Secret-%s-macos-arm64.dmg"},{"name":"checksums.txt"},{"name":"appcast.xml"}]}\n' \
  "$tag" "${TEST_DRAFT:-false}" "${TEST_PRERELEASE:-false}" "$tag"
SH
cat >"$scratch/aws" <<'SH'
#!/bin/sh
touch "$TEST_ACCESS_MARKER"
exit 88
SH
cp "$scratch/aws" "$scratch/curl"
chmod +x "$scratch/git" "$scratch/gh" "$scratch/aws" "$scratch/curl"
export PATH="$scratch:$PATH"
export AGENT_SECRET_UPDATE_FEED_URL=https://updates.agent-secret.sh/appcast.xml
export AGENT_SECRET_UPDATE_R2_BUCKET=synthetic-fixture
export AGENT_SECRET_UPDATE_R2_ENDPOINT=https://1234567890abcdef1234567890abcdef.r2.cloudflarestorage.com
export TEST_ACCESS_MARKER="$scratch/accessed"

expect_rejection() {
  local expected="$1" tag="$2"
  if "$script_dir/promote-update-feed.sh" "$tag" >"$scratch/output" 2>&1; then
    echo "test-update-feed: unexpected promotion success" >&2
    exit 1
  fi
  if ! grep -F "$expected" "$scratch/output" >/dev/null || [[ -e "$TEST_ACCESS_MARKER" ]]; then
    echo "test-update-feed: missing early rejection for $expected" >&2
    cat "$scratch/output" >&2
    exit 1
  fi
}

TEST_DRAFT=true expect_rejection "release is not stable and public" v0.0.35
TEST_PRERELEASE=true expect_rejection "release is not stable and public" v0.0.35
expect_rejection "older than the Homebrew cask" v0.0.1
"$script_dir/test-update-feed-promotion.sh"
echo "test-update-feed: ok"
