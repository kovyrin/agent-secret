#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
check_script="$project_root/scripts/release/check-release-signing-env.sh"
build_release="$project_root/scripts/release/build-release.sh"
import_certificate="$project_root/scripts/release/import-codesign-certificate.sh"
test_path="${PATH:-/usr/bin:/bin}"
# shellcheck source=../lib/bundle-metadata.sh
# shellcheck disable=SC1091
source "$project_root/scripts/lib/bundle-metadata.sh"
latest_version="$(agent_secret_latest_changelog_version "$project_root/CHANGELOG.md")"
if [[ "$latest_version" == "" ]]; then
  echo "test-release-signing-env: could not derive latest changelog version" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-release-signing-test.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  echo "test-release-signing-env: $*" >&2
  exit 1
}

expect_failure() {
  local want="$1"
  shift

  if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
    fail "expected failure containing $want"
  fi
  if ! grep -F "$want" "$tmp_dir/stderr" >/dev/null; then
    fail "stderr did not contain $want: $(cat "$tmp_dir/stderr")"
  fi
}

release_env=(
  AGENT_SECRET_CODESIGN_CERT_P12_BASE64=dummy-p12
  AGENT_SECRET_CODESIGN_CERT_PASSWORD=dummy-password
  "AGENT_SECRET_CODESIGN_IDENTITY=Developer ID Application: Oleksiy Kovyrin (B6L7QLWTZW)"
  AGENT_SECRET_NOTARY_KEY=dummy-key
  AGENT_SECRET_NOTARY_KEY_ID=dummy-key-id
  AGENT_SECRET_NOTARY_ISSUER_ID=dummy-issuer-id
)

expect_failure "missing AGENT_SECRET_CODESIGN_CERT_P12_BASE64" \
  env -i "PATH=$test_path" "$check_script"

expect_failure "AGENT_SECRET_NOTARIZE must be 1" \
  env -i "PATH=$test_path" "${release_env[@]}" AGENT_SECRET_NOTARIZE=0 "$check_script"

expect_failure "AGENT_SECRET_CODESIGN_IDENTITY must use Developer ID Team ID B6L7QLWTZW" \
  env -i "PATH=$test_path" "${release_env[@]}" \
  "AGENT_SECRET_CODESIGN_IDENTITY=Developer ID Application: Example (TEAMID)" \
  AGENT_SECRET_NOTARIZE=1 \
  "$check_script"

env -i "PATH=$test_path" "${release_env[@]}" AGENT_SECRET_NOTARIZE=1 "$check_script"

expect_failure "production signing requires AGENT_SECRET_TRUSTED_MISE" \
  env -i \
  "PATH=$test_path" \
  "${release_env[@]}" \
  AGENT_SECRET_NOTARIZE=1 \
  "$build_release" "$latest_version" --require-production-signing --output "$tmp_dir/out"

expect_failure "production signing requires AGENT_SECRET_TRUSTED_MISE" \
  env -i \
  "PATH=$test_path" \
  AGENT_SECRET_IN_MISE=1 \
  "${release_env[@]}" \
  AGENT_SECRET_NOTARIZE=1 \
  "$build_release" "$latest_version" --require-production-signing --output "$tmp_dir/out"

expect_failure "production release requires AGENT_SECRET_CODESIGN_IDENTITY" \
  env -i \
  "PATH=$test_path" \
  AGENT_SECRET_IN_MISE=1 \
  "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/out"

expect_failure "select a Keychain notarization profile or API key credentials" \
  env -i \
  "PATH=$test_path" \
  "${release_env[@]}" \
  AGENT_SECRET_IN_MISE=1 \
  AGENT_SECRET_NOTARIZE=1 \
  AGENT_SECRET_NOTARY_PROFILE=synthetic-smoke-profile \
  "$build_release" "$latest_version" --output "$tmp_dir/conflicting-notary-settings"

expect_failure "set AGENT_SECRET_CODESIGN_CERT_PASSWORD" \
  env -i \
  "PATH=$test_path" \
  AGENT_SECRET_CODESIGN_CERT_P12_BASE64=dummy-p12 \
  "$import_certificate"

echo "test-release-signing-env: ok"
