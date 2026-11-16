#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"

if [[ $# != 4 || ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: generate-update-feed.sh TAG DMG EMBEDDED_NOTES DOWNLOAD_URL_PREFIX" >&2
  exit 2
fi
tag="$1"
dmg="$2"
notes="$3"
download_base="${4%/}"
archive="Agent-Secret-$tag-macos-arm64.dmg"
tool="$project_root/approver/.build/artifacts/sparkle/Sparkle/bin/generate_appcast"
if [[ ! -x "$tool" || ! -s "$dmg" || ! -s "$notes" || "${dmg##*/}" != "$archive" || "$download_base" != https://* ]]; then
  echo "generate-update-feed: missing pinned Sparkle tool, release DMG, notes, or HTTPS download prefix" >&2
  exit 1
fi

stage="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-appcast.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
cp "$dmg" "$stage/$archive"
cp "$notes" "$stage/${archive%.dmg}.md"

# The pinned tool reads the Ed25519 seed from stdin.
"$tool" --ed-key-file - --maximum-deltas 0 --maximum-versions 1 --embed-release-notes \
  --download-url-prefix "$download_base/" "$stage"
if [[ ! -f "$stage/appcast.xml" ]]; then
  echo "generate-update-feed: Sparkle did not produce appcast.xml" >&2
  exit 1
fi
cd "$project_root"
found="$(go run ./scripts/release "$stage/appcast.xml" "$stage/$archive" "$download_base/$archive")"
if [[ "v$found" != "$tag" ]]; then
  echo "generate-update-feed: appcast release version does not match $tag" >&2
  exit 1
fi
mv "$stage/appcast.xml" "$(dirname "$dmg")/appcast.xml"
