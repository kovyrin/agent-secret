#!/usr/bin/env bash
set -euo pipefail

missing=0
expected_team_id="B6L7QLWTZW"

require_env() {
  local name="$1"

  if [[ -z "${!name:-}" ]]; then
    echo "release signing configuration: missing $name" >&2
    missing=1
  fi
}

require_env AGENT_SECRET_CODESIGN_CERT_P12_BASE64
require_env AGENT_SECRET_CODESIGN_CERT_PASSWORD
require_env AGENT_SECRET_CODESIGN_IDENTITY
require_env AGENT_SECRET_NOTARIZE
require_env AGENT_SECRET_NOTARY_KEY
require_env AGENT_SECRET_NOTARY_KEY_ID
require_env AGENT_SECRET_NOTARY_ISSUER_ID

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

if [[ "$AGENT_SECRET_NOTARIZE" != "1" ]]; then
  echo "release signing configuration: AGENT_SECRET_NOTARIZE must be 1 for tag releases" >&2
  exit 1
fi

if [[ ! "$AGENT_SECRET_CODESIGN_IDENTITY" =~ \(${expected_team_id}\)$ ]]; then
  echo "release signing configuration: AGENT_SECRET_CODESIGN_IDENTITY must use Developer ID Team ID $expected_team_id" >&2
  exit 1
fi
