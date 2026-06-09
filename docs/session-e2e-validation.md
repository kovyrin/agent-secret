# Session E2E Validation

Use this runbook to manually re-test bounded sessions against the real
CLI, background helper, native approver, provider resolver, audit log, and
child-process environment injection path.

The test uses two test-only secret references. It never prints resolved values.
The child commands only assert whether expected environment variables are
present.

## Preconditions

1. Install the current development build:

   ```bash
   mise run dev:install
   agent-secret doctor
   ```

2. Make sure `agent-secret doctor` reports:

   - `Background helper: ok`
   - `native approver: ok`
   - `1password desktop integration: ok`

3. Confirm the integration test refs are available to the local 1Password
   account:

   - `op://Agent Secret Integration/Test Secret/password`
   - `op://Agent Secret Integration/Another Test Secret/password`

## Run

The script creates a temporary project config with one secret from a profile and
adds the second secret with a CLI `--secret` flag. Approve the native prompts
when they appear.

<!-- markdownlint-disable MD013 -->

```bash
set -euo pipefail

profile_ref="${AGENT_SECRET_E2E_PROFILE_REF:-op://Agent Secret Integration/Test Secret/password}"
cli_ref="${AGENT_SECRET_E2E_CLI_REF:-op://Agent Secret Integration/Another Test Secret/password}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-session-e2e.XXXXXX")"
SESSION_ID=""
EXHAUST_ID=""

cleanup() {
  if [[ -n "${SESSION_ID:-}" ]]; then
    agent-secret session destroy "$SESSION_ID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${EXHAUST_ID:-}" ]]; then
    agent-secret session destroy "$EXHAUST_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

audit_log="$HOME/Library/Logs/agent-secret/audit.jsonl"
start_lines=0
if [[ -f "$audit_log" ]]; then
  start_lines="$(wc -l < "$audit_log" | tr -d ' ')"
fi

cd "$workdir"
cat > agent-secret.yml <<YAML
version: 1
profiles:
  session-e2e:
    reason: Agent Secret session E2E multi-secret validation
    ttl: 2m
    secrets:
      SESSION_E2E_PROFILE_TOKEN: "$profile_ref"
YAML

check_py='import os, sys
mode = sys.argv[1]
keys = ("SESSION_E2E_PROFILE_TOKEN", "SESSION_E2E_CLI_TOKEN")
wants = {
    "full": (True, True),
    "profile": (True, False),
    "cli": (False, True),
    "both": (True, True),
}
want = wants[mode]
for key, expected in zip(keys, want):
    present = bool(os.environ.get(key))
    if present != expected:
        raise SystemExit(f"{mode}: {key} present={present}, want={expected}")
print(f"{mode} ok")'

run_with_session() {
  env -u SESSION_E2E_PROFILE_TOKEN -u SESSION_E2E_CLI_TOKEN \
    agent-secret with-session "$@"
}

SESSION_JSON="$(env -u SESSION_E2E_PROFILE_TOKEN -u SESSION_E2E_CLI_TOKEN \
  agent-secret session create \
    --json \
    --profile session-e2e \
    --secret "SESSION_E2E_CLI_TOKEN=$cli_ref" \
    --max-reads 5)"
SESSION_ID="$(printf '%s' "$SESSION_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')"
printf 'created mixed config+CLI session: %s\n' "$SESSION_ID"

agent-secret session list --json |
  SESSION_ID="$SESSION_ID" python3 -c '
import json, os, sys
data = json.load(sys.stdin)
sid = os.environ["SESSION_ID"]
matches = [s for s in data["sessions"] if s["session_id"] == sid]
assert len(matches) == 1, matches
s = matches[0]
assert s["remaining_reads"] == 5, s
assert s["secret_aliases"] == [
    "SESSION_E2E_CLI_TOKEN",
    "SESSION_E2E_PROFILE_TOKEN",
], s
print("session list ok")'

run_with_session "$SESSION_ID" \
  --allow-mutable-executable \
  -- python3 -c "$check_py" full
run_with_session "$SESSION_ID" \
  --only SESSION_E2E_PROFILE_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" profile

missing_output="$workdir/missing-alias.out"
if run_with_session "$SESSION_ID" \
  --only SESSION_E2E_MISSING_TOKEN \
  --allow-mutable-executable \
  -- python3 -c 'print("UNEXPECTED_CHILD_STARTED")' \
  >"$missing_output" 2>&1; then
  echo 'BUG: missing alias unexpectedly succeeded' >&2
  exit 1
fi
if grep -q 'UNEXPECTED_CHILD_STARTED' "$missing_output"; then
  echo 'BUG: missing alias spawned child' >&2
  exit 1
fi
echo 'missing alias rejected before child spawn'

run_with_session "$SESSION_ID" \
  --only SESSION_E2E_CLI_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" cli
run_with_session "$SESSION_ID" \
  --only SESSION_E2E_PROFILE_TOKEN,SESSION_E2E_CLI_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" both

agent-secret session list --json |
  SESSION_ID="$SESSION_ID" python3 -c '
import json, os, sys
data = json.load(sys.stdin)
sid = os.environ["SESSION_ID"]
matches = [s for s in data["sessions"] if s["session_id"] == sid]
assert len(matches) == 1, matches
assert matches[0]["remaining_reads"] == 1, matches[0]
print("read count after subset runs ok")'

agent-secret session destroy "$SESSION_ID" >/dev/null
destroyed_output="$workdir/destroyed.out"
if run_with_session "$SESSION_ID" \
  --only SESSION_E2E_PROFILE_TOKEN \
  --allow-mutable-executable \
  -- python3 -c 'print("UNEXPECTED_CHILD_STARTED")' \
  >"$destroyed_output" 2>&1; then
  echo 'BUG: destroyed session unexpectedly resolved' >&2
  exit 1
fi
if grep -q 'UNEXPECTED_CHILD_STARTED' "$destroyed_output"; then
  echo 'BUG: destroyed session spawned child' >&2
  exit 1
fi
echo 'destroyed session rejected before child spawn'
SESSION_ID=""

EXHAUST_JSON="$(env -u SESSION_E2E_PROFILE_TOKEN -u SESSION_E2E_CLI_TOKEN \
  agent-secret session create \
    --json \
    --profile session-e2e \
    --secret "SESSION_E2E_CLI_TOKEN=$cli_ref" \
    --max-reads 1)"
EXHAUST_ID="$(printf '%s' "$EXHAUST_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')"
printf 'created one-read session: %s\n' "$EXHAUST_ID"
run_with_session "$EXHAUST_ID" \
  --only SESSION_E2E_PROFILE_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" profile

exhausted_output="$workdir/exhausted.out"
if run_with_session "$EXHAUST_ID" \
  --only SESSION_E2E_PROFILE_TOKEN \
  --allow-mutable-executable \
  -- python3 -c 'print("UNEXPECTED_CHILD_STARTED")' \
  >"$exhausted_output" 2>&1; then
  echo 'BUG: exhausted session unexpectedly resolved' >&2
  exit 1
fi
if grep -q 'UNEXPECTED_CHILD_STARTED' "$exhausted_output"; then
  echo 'BUG: exhausted session spawned child' >&2
  exit 1
fi
echo 'read exhaustion rejected before child spawn'
EXHAUST_ID=""

python3 - "$audit_log" "$start_lines" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
start = int(sys.argv[2])
events = []
with path.open() as f:
    for index, line in enumerate(f, start=1):
        if index <= start:
            continue
        events.append(json.loads(line))

types = [event.get("type") for event in events]
for required in (
    "session_created",
    "session_resolved",
    "session_destroyed",
    "command_started",
    "command_completed",
):
    if required not in types:
        raise SystemExit(f"missing audit event {required}; saw {types}")

aliases = {
    ref.get("alias")
    for event in events
    for ref in event.get("secret_refs", [])
}
expected = {"SESSION_E2E_PROFILE_TOKEN", "SESSION_E2E_CLI_TOKEN"}
if not expected.issubset(aliases):
    raise SystemExit(
        f"audit aliases {sorted(aliases)} missing {sorted(expected)}"
    )
print("audit metadata ok")
PY

echo 'session E2E ok'
```

<!-- markdownlint-enable MD013 -->

## Expected Output

The exact session IDs vary, but a passing run prints these checkpoints:

```text
created mixed config+CLI session: asess_...
session list ok
full ok
profile ok
missing alias rejected before child spawn
cli ok
both ok
read count after subset runs ok
destroyed session rejected before child spawn
created one-read session: asess_...
profile ok
read exhaustion rejected before child spawn
audit metadata ok
session E2E ok
```

## Coverage

This E2E run proves:

- `session create` accepts secrets from a project config profile and CLI args.
- `session list` shows metadata for active sessions without values.
- `with-session` injects the full approved bag when `--only` is omitted.
- `with-session --only` injects config-only, CLI-only, and combined subsets.
- Unknown aliases fail before the child process starts.
- `session destroy` prevents further resolution.
- Read exhaustion prevents further resolution.
- Session and command lifecycle audit metadata is written.
