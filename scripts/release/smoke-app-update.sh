#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
# shellcheck source=scripts/lib/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/lib/bundle-metadata.sh"

if [[ $# != 1 ]]; then
  echo "usage: mise exec -- scripts/release/smoke-app-update.sh NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
: "${AGENT_SECRET_CODESIGN_IDENTITY:?select an existing Developer ID Application identity}"
: "${AGENT_SECRET_TRUSTED_MISE:?set the absolute path to mise}"
umask 077
mkdir "$1"
output="$(cd -- "$1" && pwd)"
mkdir "$output/feed" "$output/client"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-update-smoke.XXXXXXXX")"
trap 'rm -rf "$scratch"' EXIT
cd "$project_root"
short="$(agent_secret_latest_changelog_version "$project_root/CHANGELOG.md")"
tag="v$short"
archive="Agent-Secret-$tag-macos-arm64.dmg"
export AGENT_SECRET_UPDATE_FEED_URL="https://localhost:8443/appcast.xml"
AGENT_SECRET_UPDATE_PUBLIC_KEY="$(
  swift - "$scratch/seed" <<'SWIFT'
import CryptoKit
import Foundation
let key = Curve25519.Signing.PrivateKey()
try key.rawRepresentation.base64EncodedData().write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
print(key.publicKey.rawRepresentation.base64EncodedString())
SWIFT
)"
export AGENT_SECRET_UPDATE_PUBLIC_KEY
printf '%s\n' "$AGENT_SECRET_UPDATE_PUBLIC_KEY" >"$output/client/sparkle-public-key.txt"

# The same short release version is intentional. Only the previous build uses
# the smaller CFBundleVersion, so release signing policy need not be weakened.
AGENT_SECRET_UPDATE_SMOKE_OLDER_BUILD=1 \
  "$script_dir/build-release.sh" "$tag" --output "$scratch/old"
cp "$scratch/old/$archive" "$output/client/Agent-Secret-previous-build.dmg"
"$script_dir/build-release.sh" "$tag" --output "$output/feed"
printf '# Agent Secret %s\n\nLocal signed update validation.\n' "$tag" >"$scratch/notes.md"
"$script_dir/generate-update-feed.sh" "$tag" "$output/feed/$archive" \
  "$scratch/notes.md" "https://localhost:8443" <"$scratch/seed"
printf '%s\n' "$output"
