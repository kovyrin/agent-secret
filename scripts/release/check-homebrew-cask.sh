#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "check-homebrew-cask: $*" >&2
  exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  fail "usage: scripts/release/check-homebrew-cask.sh TAG [CASK_PATH] [CHECKSUMS_FILE]"
fi

tag="$1"
cask_path="${2:-Casks/agent-secret.rb}"
checksums_file="${3:-}"

if [[ "$tag" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]]; then
  version="${tag#v}"
else
  fail "release tag must be vX.Y.Z, got $tag"
fi

[ -f "$cask_path" ] || fail "cask file not found: $cask_path"

cask_version="$(
  awk -F\" '/^[[:space:]]*version[[:space:]]+"/ { print $2; exit }' "$cask_path"
)"
cask_sha256="$(
  awk -F\" '/^[[:space:]]*sha256[[:space:]]+"/ { print $2; exit }' "$cask_path"
)"

[ -n "$cask_version" ] || fail "missing version in $cask_path"
[ -n "$cask_sha256" ] || fail "missing sha256 in $cask_path"

if [ "$cask_version" != "$version" ]; then
  fail "cask version is $cask_version, expected $version"
fi

tmp_dir=""
cleanup() {
  if [ -n "$tmp_dir" ]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT

if [ -z "$checksums_file" ]; then
  command -v gh >/dev/null || fail "gh is required when CHECKSUMS_FILE is not provided"
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-homebrew-cask.XXXXXX")"
  gh release download "$tag" --pattern checksums.txt --dir "$tmp_dir"
  checksums_file="$tmp_dir/checksums.txt"
fi

[ -f "$checksums_file" ] || fail "checksums file not found: $checksums_file"

artifact="Agent-Secret-${tag}-macos-arm64.dmg"
release_sha256="$(
  awk -v artifact="$artifact" '$2 == artifact { print $1; found = 1 } END { if (!found) exit 1 }' "$checksums_file"
)" || fail "missing checksum for $artifact in $checksums_file"

if [[ ! "$release_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  fail "checksum for $artifact is not a SHA-256 hex digest"
fi

if [ "$cask_sha256" != "$release_sha256" ]; then
  fail "cask sha256 is $cask_sha256, expected $release_sha256"
fi

echo "check-homebrew-cask: ok ($tag $release_sha256)"
