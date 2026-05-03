#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
check_script="$project_root/scripts/check-release-signing-env.sh"
build_release="$project_root/scripts/build-release.sh"
import_certificate="$project_root/scripts/import-codesign-certificate.sh"
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

expect_any_failure() {
  if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
    fail "expected command to fail"
  fi
}

write_path_trap_tools() {
  local trap_dir="$1"
  local log="$2"
  local tool=""

  mkdir -p "$trap_dir"
  for tool in base64 security uuidgen codesign xcrun ditto hdiutil shasum; do
    cat >"$trap_dir/$tool" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$(basename "$0") $*" >>"$AGENT_SECRET_PATH_TRAP_LOG"
exit 44
BASH
    chmod 755 "$trap_dir/$tool"
  done
  : >"$log"
}

assert_path_trap_clean() {
  local log="$1"

  if [[ -s "$log" ]]; then
    fail "release script executed PATH trap tool: $(cat "$log")"
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
  env -i "PATH=$test_path" "${release_env[@]}" "AGENT_SECRET_CODESIGN_IDENTITY=Developer ID Application: Example (TEAMID)" AGENT_SECRET_NOTARIZE=1 "$check_script"

env -i "PATH=$test_path" "${release_env[@]}" AGENT_SECRET_NOTARIZE=1 "$check_script"

expect_failure "production release requires AGENT_SECRET_CODESIGN_IDENTITY" \
  env -i "PATH=$test_path" AGENT_SECRET_IN_MISE=1 "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/out"

trap_dir="$tmp_dir/path-trap-bin"
trap_log="$tmp_dir/path-trap.log"
write_path_trap_tools "$trap_dir" "$trap_log"

expect_any_failure \
  env -i \
  "PATH=$trap_dir:$test_path" \
  AGENT_SECRET_PATH_TRAP_LOG="$trap_log" \
  AGENT_SECRET_CODESIGN_CERT_P12_BASE64=not-base64 \
  AGENT_SECRET_CODESIGN_CERT_PASSWORD=dummy-password \
  "$import_certificate"
assert_path_trap_clean "$trap_log"

expect_failure "production release requires AGENT_SECRET_CODESIGN_IDENTITY" \
  env -i \
  "PATH=$trap_dir:$test_path" \
  AGENT_SECRET_PATH_TRAP_LOG="$trap_log" \
  AGENT_SECRET_IN_MISE=1 \
  "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/path-trap-out"
assert_path_trap_clean "$trap_log"

if grep -En '(^|[|;&][[:space:]]*)(base64|security|uuidgen)([[:space:]]|$)' "$import_certificate"; then
  fail "import-codesign-certificate.sh contains bare secret-handling tool invocation"
fi
if grep -En '(^|[|;&][[:space:]]*)(codesign|xcrun|ditto|hdiutil|shasum)([[:space:]]|$)' \
  "$build_release" "$project_root/scripts/build-app-bundle.sh"; then
  fail "release build scripts contain bare Apple tool invocation"
fi

echo "test-release-signing-env: ok"
