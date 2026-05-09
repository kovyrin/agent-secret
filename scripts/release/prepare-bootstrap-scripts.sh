#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"

fail() {
  echo "prepare bootstrap scripts: $*" >&2
  exit 1
}

if [ "$#" -ne 2 ]; then
  fail "usage: scripts/release/prepare-bootstrap-scripts.sh TAG OUTPUT_DIR"
fi

tag="$1"
output_dir="$2"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  fail "release tag must be vX.Y.Z, got $tag"
fi

mkdir -p "$output_dir"

install_output="$output_dir/install.sh"
uninstall_output="$output_dir/uninstall.sh"

awk -v tag="$tag" '
  BEGIN { replaced = 0 }
  /^release_asset_version=""/ {
    print "release_asset_version=\"" tag "\""
    replaced = 1
    next
  }
  { print }
  END {
    if (!replaced) {
      exit 1
    }
  }
' "$project_root/install.sh" >"$install_output" ||
  fail "could not stamp install.sh with $tag"

cp "$project_root/uninstall.sh" "$uninstall_output"
chmod 755 "$install_output" "$uninstall_output"

if ! grep -F -- "release_asset_version=\"$tag\"" "$install_output" >/dev/null; then
  fail "stamped install.sh does not contain $tag"
fi
