#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
check_script="$project_root/scripts/check-release-signing-env.sh"
build_release="$project_root/scripts/build-release.sh"
test_path="${PATH:-/usr/bin:/bin}"

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
  "AGENT_SECRET_CODESIGN_IDENTITY=Developer ID Application: Example (TEAMID)"
  AGENT_SECRET_NOTARY_KEY=dummy-key
  AGENT_SECRET_NOTARY_KEY_ID=dummy-key-id
  AGENT_SECRET_NOTARY_ISSUER_ID=dummy-issuer-id
)

expect_failure "missing AGENT_SECRET_CODESIGN_CERT_P12_BASE64" \
  env -i "PATH=$test_path" "$check_script"

expect_failure "AGENT_SECRET_NOTARIZE must be 1" \
  env -i "PATH=$test_path" "${release_env[@]}" AGENT_SECRET_NOTARIZE=0 "$check_script"

env -i "PATH=$test_path" "${release_env[@]}" AGENT_SECRET_NOTARIZE=1 "$check_script"

expect_failure "production release requires AGENT_SECRET_CODESIGN_IDENTITY" \
  env -i "PATH=$test_path" AGENT_SECRET_IN_MISE=1 "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/out"

echo "test-release-signing-env: ok"
