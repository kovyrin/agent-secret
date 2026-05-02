#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/build-release.sh VERSION [flags]

Build a local macOS DMG release artifact and checksums.txt.

Flags:
  --output DIR   Output directory. Defaults to ./dist.
  -h, --help     Show this help.
USAGE
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
output_dir="$project_root/dist"

if [[ "${AGENT_SECRET_IN_MISE:-}" != "1" ]]; then
  if command -v mise >/dev/null 2>&1; then
    export AGENT_SECRET_IN_MISE=1
    exec mise exec -- "$0" "$@"
  fi
fi

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 2
fi

version=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      if [[ $# -lt 2 || "$2" == "" ]]; then
        echo "build-release: --output requires a directory" >&2
        exit 2
      fi
      output_dir="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "build-release: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ "$version" != "" ]]; then
        echo "build-release: version was already set to $version" >&2
        exit 2
      fi
      version="$1"
      shift
      ;;
  esac
done

if [[ "$version" == "" ]]; then
  echo "build-release: VERSION is required" >&2
  exit 2
fi

require_command() {
  local name="$1"

  if ! command -v "$name" >/dev/null 2>&1; then
    echo "build-release: required command not found: $name" >&2
    exit 1
  fi
}

case "$(uname -m)" in
  arm64)
    arch="arm64"
    ;;
  x86_64)
    arch="x86_64"
    ;;
  *)
    echo "build-release: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

require_command hdiutil
require_command ditto
require_command shasum

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

build_dir="$tmp_dir/build"
dmg_root="$tmp_dir/dmg-root"
artifact_name="Agent-Secret-$version-macos-$arch.dmg"
dmg_path="$output_dir/$artifact_name"
checksums_path="$output_dir/checksums.txt"

echo "Building Agent Secret.app for $version..."
"$project_root/scripts/build-app-bundle.sh" --version "$version" --output "$build_dir"

echo "Preparing DMG contents..."
rm -rf "$dmg_root"
mkdir -p "$dmg_root"
ditto "$build_dir/Agent Secret.app" "$dmg_root/Agent Secret.app"
ln -s /Applications "$dmg_root/Applications"

echo "Creating $dmg_path..."
mkdir -p "$output_dir"
rm -f "$dmg_path"
hdiutil create \
  -volname "Agent Secret $version" \
  -srcfolder "$dmg_root" \
  -format UDZO \
  -ov \
  "$dmg_path" >/dev/null

echo "Verifying DMG..."
hdiutil verify "$dmg_path" >/dev/null

echo "Writing checksums..."
(
  cd "$output_dir"
  shasum -a 256 "$artifact_name" >"$checksums_path"
)

echo "$dmg_path"
echo "$checksums_path"
