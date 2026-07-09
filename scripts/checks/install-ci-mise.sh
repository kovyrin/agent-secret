#!/usr/bin/env bash
set -euo pipefail

version="${AGENT_SECRET_MISE_VERSION:-}"
expected_sha256="${AGENT_SECRET_MISE_SHA256_MACOS_ARM64:-}"

if [ -z "$version" ]; then
  echo "install-ci-mise: AGENT_SECRET_MISE_VERSION is required" >&2
  exit 1
fi

if [ -z "$expected_sha256" ]; then
  echo "install-ci-mise: AGENT_SECRET_MISE_SHA256_MACOS_ARM64 is required" >&2
  exit 1
fi

case "$(uname -s):$(uname -m)" in
  Darwin:arm64)
    platform="macos-arm64"
    ;;
  *)
    echo "install-ci-mise: unsupported runner $(uname -s):$(uname -m)" >&2
    exit 1
    ;;
esac

base_tmp="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
tmp_dir="$(mktemp -d "$base_tmp/agent-secret-mise.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

url="https://github.com/jdx/mise/releases/download/v${version}/mise-v${version}-${platform}"
download="$tmp_dir/mise"
asset_name="mise-v${version}-${platform}"
target="$HOME/.local/share/mise/bin/mise"

if ! curl \
  --fail \
  --location \
  --show-error \
  --silent \
  --retry 6 \
  --retry-all-errors \
  --retry-delay 5 \
  --connect-timeout 20 \
  --max-time 300 \
  --output "$download" \
  "$url"; then
  echo "install-ci-mise: direct download failed, trying GitHub release API" >&2
  if ! command -v gh >/dev/null; then
    echo "install-ci-mise: gh is required for release API fallback" >&2
    exit 1
  fi

  rm -f "$download"
  gh release download "v${version}" \
    --repo jdx/mise \
    --pattern "$asset_name" \
    --dir "$tmp_dir"
  mv "$tmp_dir/$asset_name" "$download"
fi

actual_sha256="$(shasum -a 256 "$download" | awk '{print $1}')"
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "install-ci-mise: checksum mismatch for $url" >&2
  echo "install-ci-mise: expected $expected_sha256" >&2
  echo "install-ci-mise: actual   $actual_sha256" >&2
  exit 1
fi

mkdir -p "$(dirname "$target")"
install -m 0755 "$download" "$target"

if [ -n "${GITHUB_PATH:-}" ]; then
  dirname "$target" >>"$GITHUB_PATH"
fi

"$target" --version
