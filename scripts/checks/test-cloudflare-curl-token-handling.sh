#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/../.." && pwd)"
deploy_script="$project_root/scripts/deploy-site.sh"

fail() {
  echo "test-cloudflare-curl-token-handling: $*" >&2
  exit 1
}

require_text() {
  local needle="$1"

  if ! grep -F -- "$needle" "$deploy_script" >/dev/null; then
    fail "deploy-site.sh is missing expected Cloudflare curl handling: $needle"
  fi
}

reject_text() {
  local needle="$1"

  if grep -F -- "$needle" "$deploy_script" >/dev/null; then
    fail "deploy-site.sh still contains unsafe Cloudflare curl handling: $needle"
  fi
}

require_text "printf 'header = \"Authorization: Bearer %s\"\\n' \"\$CLOUDFLARE_API_TOKEN\""
require_text 'curl -fsS --config - "$@"'

reject_text "config=\"\$(mktemp)\""
reject_text "chmod 600 \"\$config\""
reject_text "--config \"\$config\""
reject_text "rm -f \"\$config\""
reject_text ">\"\$config\""

if grep -E -- '(^|[[:space:]])(-H|--header)([[:space:]]|=)' "$deploy_script" |
  grep -F 'CLOUDFLARE_API_TOKEN' >/dev/null; then
  fail "Cloudflare API token must not be passed in curl process arguments"
fi

echo "test-cloudflare-curl-token-handling: ok"
