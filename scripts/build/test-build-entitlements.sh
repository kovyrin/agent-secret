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

if ! grep -F "agent-secret exec" "$build_script" >/dev/null ||
  ! grep -F -- "--profile bundled-gcp-oauth-client" "$build_script" >/dev/null ||
  ! grep -F -- "--override-env" "$build_script" >/dev/null; then
  fail "build script must use the bundled-gcp-oauth-client profile when OAuth client env vars are absent"
fi

if ! grep -F "AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_ID" "$project_root/agent-secret.yml" >/dev/null ||
  ! grep -F "AGENT_SECRET_BUNDLED_GCP_OAUTH_CLIENT_SECRET" "$project_root/agent-secret.yml" >/dev/null; then
  fail "agent-secret.yml must define bundled GCP OAuth client build secrets"
fi

echo "test-build-entitlements: ok"
