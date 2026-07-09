#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
build_script="$project_root/scripts/build/build-app-bundle.sh"
entitlements="$project_root/scripts/build/agent-secretd.entitlements"

fail() {
  echo "test-build-entitlements: $*" >&2
  exit 1
}

if ! /usr/libexec/PlistBuddy \
  -c "Print :com.apple.security.cs.disable-library-validation" \
  "$entitlements" |
  grep -Fx "true" >/dev/null; then
  fail "daemon entitlements must disable library validation for the 1Password SDK dylib"
fi

if grep -F "AGENT_SECRET_CODESIGN_ENTITLEMENTS" "$build_script" >/dev/null; then
  fail "production signing must not depend on caller-provided entitlements"
fi

if ! grep -F "daemon_entitlements=\"\$project_root/scripts/build/agent-secretd.entitlements\"" "$build_script" >/dev/null; then
  fail "build script must use the checked-in daemon entitlements file"
fi

if ! grep -F "sign_path \"\$app_bundle/Contents/Library/Helpers/AgentSecretDaemon.app\" \"\$daemon_entitlements\"" "$build_script" >/dev/null; then
  fail "daemon helper app must be signed with daemon entitlements"
fi

if ! grep -F "sign_path \"\$app_bundle/Contents/Resources/bin/agent-secret\"" "$build_script" >/dev/null; then
  fail "bundled CLI executable must be signed separately"
fi

echo "test-build-entitlements: ok"
