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
  for tool in bash dirname base64 security uuidgen codesign xcrun ditto hdiutil shasum \
    mktemp rm mkdir ln chmod install cp sips iconutil go swift uname mise; do
    cat >"$trap_dir/$tool" <<'BASH'
#!/bin/sh
set -eu
printf '%s\n' "${0##*/} $*" >>"$AGENT_SECRET_PATH_TRAP_LOG"
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

expect_failure "refusing to re-exec PATH-discovered mise while release signing environment is present" \
  env -i \
  "PATH=$trap_dir:$test_path" \
  AGENT_SECRET_PATH_TRAP_LOG="$trap_log" \
  "${release_env[@]}" \
  AGENT_SECRET_NOTARIZE=1 \
  "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/mise-trap-out"
assert_path_trap_clean "$trap_log"

unsafe_keychain="$tmp_dir/unrelated-user-file"
dummy_cert="$tmp_dir/dummy.p12"
printf 'keep\n' >"$unsafe_keychain"
printf 'not a real certificate\n' >"$dummy_cert"

expect_failure "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH filename must be agent-secret-codesign*.keychain-db" \
  env -i \
  "PATH=$test_path" \
  AGENT_SECRET_CODESIGN_CERT_P12_PATH="$dummy_cert" \
  AGENT_SECRET_CODESIGN_CERT_PASSWORD=dummy-password \
  AGENT_SECRET_CODESIGN_KEYCHAIN_PATH="$unsafe_keychain" \
  "$import_certificate"

if [[ "$(cat "$unsafe_keychain")" != "keep" ]]; then
  fail "unsafe custom keychain path was modified"
fi

unsafe_keychain_dir="$tmp_dir/outside-temp"
unsafe_keychain="$unsafe_keychain_dir/agent-secret-codesign.keychain-db"
mkdir -p "$unsafe_keychain_dir"
printf 'keep\n' >"$unsafe_keychain"

expect_failure "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH must be under trusted temp directory" \
  env -i \
  "PATH=$test_path" \
  RUNNER_TEMP="$tmp_dir/runner-temp" \
  AGENT_SECRET_CODESIGN_CERT_P12_PATH="$dummy_cert" \
  AGENT_SECRET_CODESIGN_CERT_PASSWORD=dummy-password \
  AGENT_SECRET_CODESIGN_KEYCHAIN_PATH="$unsafe_keychain" \
  "$import_certificate"

if [[ "$(cat "$unsafe_keychain")" != "keep" ]]; then
  fail "custom keychain path outside trusted temp was modified"
fi

runner_temp="$tmp_dir/runner-temp"
symlink_target="$tmp_dir/symlink-target"
symlink_parent="$runner_temp/keychains-link"
unsafe_keychain="$symlink_parent/agent-secret-codesign.keychain-db"
mkdir -p "$runner_temp" "$symlink_target"
printf 'keep\n' >"$symlink_target/agent-secret-codesign.keychain-db"
ln -s "$symlink_target" "$symlink_parent"

expect_failure "AGENT_SECRET_CODESIGN_KEYCHAIN_PATH must not contain symlinked parent directories" \
  env -i \
  "PATH=$test_path" \
  RUNNER_TEMP="$runner_temp" \
  AGENT_SECRET_CODESIGN_CERT_P12_PATH="$dummy_cert" \
  AGENT_SECRET_CODESIGN_CERT_PASSWORD=dummy-password \
  AGENT_SECRET_CODESIGN_KEYCHAIN_PATH="$unsafe_keychain" \
  "$import_certificate"

if [[ "$(cat "$symlink_target/agent-secret-codesign.keychain-db")" != "keep" ]]; then
  fail "custom keychain path through symlinked parent was modified"
fi

expect_failure "production release requires AGENT_SECRET_CODESIGN_IDENTITY" \
  env -i \
  "PATH=$trap_dir:$test_path" \
  AGENT_SECRET_PATH_TRAP_LOG="$trap_log" \
  AGENT_SECRET_IN_MISE=1 \
  "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/path-trap-out"
assert_path_trap_clean "$trap_log"

fake_goroot="$tmp_dir/fake-goroot"
fake_goroot_log="$tmp_dir/fake-goroot.log"
trusted_go="$(command -v go || true)"
if [[ "$trusted_go" == "" ]] && command -v mise >/dev/null 2>&1; then
  trusted_go="$(mise exec -- command -v go || true)"
fi
if [[ "$trusted_go" == "" || "$trusted_go" != /* ]]; then
  fail "could not locate trusted go for GOROOT trap test"
fi
trusted_go_path="${trusted_go%/*}:$test_path"
mkdir -p "$fake_goroot/bin"
cat >"$fake_goroot/bin/go" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "fake-goroot-go $*" >>"$AGENT_SECRET_FAKE_GOROOT_LOG"
exit 44
BASH
chmod 755 "$fake_goroot/bin/go"
: >"$fake_goroot_log"

expect_failure "inherited GOROOT does not match selected Go toolchain" \
  env -i \
  "PATH=$trusted_go_path" \
  AGENT_SECRET_FAKE_GOROOT_LOG="$fake_goroot_log" \
  "${release_env[@]}" \
  AGENT_SECRET_NOTARIZE=1 \
  AGENT_SECRET_IN_MISE=1 \
  GOROOT="$fake_goroot" \
  "$build_release" v0.0.0 --require-production-signing --output "$tmp_dir/goroot-trap-out"
if [[ -s "$fake_goroot_log" ]]; then
  fail "release script executed fake GOROOT go: $(cat "$fake_goroot_log")"
fi

release_sensitive_scripts=(
  "$build_release"
  "$project_root/scripts/build-app-bundle.sh"
  "$project_root/scripts/check-bundle-metadata.sh"
  "$project_root/scripts/check-release-signing-env.sh"
  "$import_certificate"
  "$project_root/scripts/publish-draft-release.sh"
)
for script in "${release_sensitive_scripts[@]}"; do
  read -r shebang <"$script"
  if [[ "$shebang" != "#!/bin/bash" ]]; then
    fail "$script must use fixed /bin/bash shebang"
  fi
done
if grep -En 'dirname[[:space:]]+--[[:space:]]+"\$\{BASH_SOURCE\[0\]\}"' \
  "$build_release" \
  "$project_root/scripts/build-app-bundle.sh" \
  "$project_root/scripts/check-bundle-metadata.sh"; then
  fail "release bootstrap scripts must not use PATH-selected dirname"
fi

if grep -En '(^|[|;&][[:space:]]*)(base64|security|uuidgen|mktemp|rm|chmod)([[:space:]]|$)' "$import_certificate"; then
  fail "import-codesign-certificate.sh contains bare secret-handling tool invocation"
fi
if grep -En '(^|[|;&][[:space:]]*)(codesign|xcrun|ditto|hdiutil|shasum|mktemp|rm|mkdir|ln|chmod|install|cp|sips|iconutil|go|swift|uname)([[:space:]]|$)' \
  "$build_release" "$project_root/scripts/build-app-bundle.sh"; then
  fail "release build scripts contain bare Apple tool invocation"
fi

echo "test-release-signing-env: ok"
