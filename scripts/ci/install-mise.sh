#!/usr/bin/env bash
set -euo pipefail

version="${AGENT_SECRET_MISE_VERSION:-}"
expected_sha256="${AGENT_SECRET_MISE_SHA256_MACOS_ARM64:-}"

if [[ "$version" == "" ]]; then
  echo "install-mise: AGENT_SECRET_MISE_VERSION is required" >&2
  exit 1
fi
if [[ "$expected_sha256" == "" ]]; then
  echo "install-mise: AGENT_SECRET_MISE_SHA256_MACOS_ARM64 is required" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
  echo "install-mise: this installer currently supports macOS arm64 runners only" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-mise.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

mise_url="https://github.com/jdx/mise/releases/download/v${version}/mise-v${version}-macos-arm64"
mise_path="$tmp_dir/mise"
install_dir="${AGENT_SECRET_MISE_INSTALL_DIR:-$HOME/.local/bin}"
installed_mise="$install_dir/mise"

curl -fsSL "$mise_url" -o "$mise_path"
actual_sha256="$(shasum -a 256 "$mise_path" | awk '{print $1}')"
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "install-mise: SHA-256 mismatch for $mise_url" >&2
  echo "install-mise: expected $expected_sha256" >&2
  echo "install-mise: actual   $actual_sha256" >&2
  exit 1
fi

install -d -m 0755 "$install_dir"
install -m 0755 "$mise_path" "$installed_mise"
if [[ "${GITHUB_PATH:-}" != "" ]]; then
  printf '%s\n' "$install_dir" >>"$GITHUB_PATH"
fi

"$installed_mise" --version
