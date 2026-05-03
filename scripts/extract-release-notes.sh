#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "release notes: $*" >&2
  exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  fail "usage: scripts/extract-release-notes.sh TAG [OUTPUT] [CHANGELOG]"
fi

tag="$1"
output="${2:-}"
changelog="${3:-CHANGELOG.md}"

if [[ "$tag" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  version="${tag#v}"
else
  fail "release tag must be vX.Y.Z, got $tag"
fi

[ -f "$changelog" ] || fail "changelog not found: $changelog"

tmp="$(mktemp "${TMPDIR:-/tmp}/agent-secret-release-notes.XXXXXX")"
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

awk -v version="$version" '
function fail(msg) {
  print "release notes: " msg > "/dev/stderr"
  failed = 1
  exit 1
}

BEGIN {
  header_prefix = "## [" version "] - "
}

done {
  next
}

index($0, header_prefix) == 1 {
  suffix = substr($0, length(header_prefix) + 1)
  found = 1
  if (suffix == "Pending") {
    fail("changelog section for v" version " is still Pending")
  }
  if (suffix !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
    fail("changelog section for v" version " must use YYYY-MM-DD date")
  }
  in_section = 1
  print
  next
}

in_section && /^## / {
  in_section = 0
  done = 1
  next
}

in_section {
  print
  if ($0 ~ /[^[:space:]]/) {
    body = 1
  }
}

END {
  if (failed) {
    exit 1
  }
  if (!found) {
    fail("missing changelog section for v" version)
  }
  if (!body) {
    fail("changelog section for v" version " is empty")
  }
}
' "$changelog" >"$tmp"

if [ -n "$output" ]; then
  mkdir -p "$(dirname "$output")"
  mv "$tmp" "$output"
  trap - EXIT
else
  cat "$tmp"
fi
