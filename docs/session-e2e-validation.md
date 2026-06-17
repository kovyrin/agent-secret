# Session E2E Validation

Use this runbook to manually re-test bounded sessions against the real CLI,
background helper, native approver, provider resolver, audit log,
child-process environment injection path, and requester process-tree binding.

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

4. Run from a macOS user session where `launchctl submit` can start a per-user
   helper job. The detached replay check intentionally launches a requester
   outside the shell that created the session.

## Run

The script creates a temporary project config with one secret from a profile and
adds the second secret with a CLI `--secret` flag. It creates and consumes each
session inside one shell so `with-session` runs from the approved requester
process tree, uses profile and name-based explicit ancestor binding, then
submits a launchd helper to prove the same token cannot be used from a different
requester process tree. Approve the native prompts when they appear.

<!-- markdownlint-disable MD013 -->

```bash
set -euo pipefail

profile_ref="${AGENT_SECRET_E2E_PROFILE_REF:-op://Agent Secret Integration/Test Secret/password}"
cli_ref="${AGENT_SECRET_E2E_CLI_REF:-op://Agent Secret Integration/Another Test Secret/password}"
agent_secret_bin="$(command -v agent-secret)"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-session-e2e.XXXXXX")"
chmod 700 "$workdir"
SESSION_ID=""
SESSION_TOKEN=""
EXHAUST_ID=""
EXHAUST_TOKEN=""
DETACHED_LABEL=""

cleanup() {
  if [[ -n "${DETACHED_LABEL:-}" ]]; then
    launchctl remove "$DETACHED_LABEL" >/dev/null 2>&1 || true
  fi
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
    session:
      bind: parent
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
    --json=compact \
    --profile session-e2e \
    --secret "SESSION_E2E_CLI_TOKEN=$cli_ref" \
    --max-reads 5)"
SESSION_ID="$(printf '%s' "$SESSION_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')"
SESSION_TOKEN="$(printf '%s' "$SESSION_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')"
printf 'created mixed config+CLI session: %s\n' "$SESSION_ID"

agent-secret session list --json=compact |
  python3 -c 'import os, json, sys
session_id = sys.argv[1]
data = json.load(sys.stdin)
matches = [
    s for s in data["sessions"]
    if s["session_id"] == session_id
    and s["remaining_reads"] == 5 and s["secret_aliases"] == [
        "SESSION_E2E_CLI_TOKEN",
        "SESSION_E2E_PROFILE_TOKEN",
    ]
]
assert len(matches) >= 1, data
assert matches[0]["cwd"] == os.getcwd(), matches[0]
assert "session_token" not in matches[0], matches[0]
binding = matches[0]["session_binding"]
assert binding["mode"] == "ancestor", binding
assert binding["ancestor_depth"] == 1, binding
assert binding["bound_process"]["pid"] > 1, binding
assert binding["bound_process"]["path"], binding
print("session list and binding metadata ok")' "$SESSION_ID"

run_with_session "$SESSION_TOKEN" \
  --allow-mutable-executable \
  -- python3 -c "$check_py" full
run_with_session "$SESSION_TOKEN" \
  --only SESSION_E2E_PROFILE_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" profile

detached_dir="$workdir/detached-replay"
mkdir -p "$detached_dir"
chmod 700 "$detached_dir"
detached_helper="$detached_dir/replay.sh"
detached_token_file="$detached_dir/session-token"
detached_output="$detached_dir/output"
detached_status="$detached_dir/status"
printf '%s' "$SESSION_TOKEN" > "$detached_token_file"
chmod 600 "$detached_token_file"
cat > "$detached_helper" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

agent_secret_bin="$1"
workdir="$2"
token_file="$3"
output_file="$4"
status_file="$5"

cd "$workdir"
token="$(cat "$token_file")"
set +e
env -u SESSION_E2E_PROFILE_TOKEN -u SESSION_E2E_CLI_TOKEN \
  "$agent_secret_bin" with-session "$token" \
    --only SESSION_E2E_PROFILE_TOKEN \
    --allow-mutable-executable \
    -- python3 -c 'print("UNEXPECTED_CHILD_STARTED")' \
    >"$output_file" 2>&1
exit_code="$?"
set -e
printf '%s\n' "$exit_code" > "$status_file"
SH
chmod 700 "$detached_helper"

DETACHED_LABEL="com.kovyrin.agent-secret.session-e2e.$RANDOM.$RANDOM"
launchctl submit -l "$DETACHED_LABEL" -- \
  "$detached_helper" \
  "$agent_secret_bin" \
  "$workdir" \
  "$detached_token_file" \
  "$detached_output" \
  "$detached_status"
for _ in {1..150}; do
  if [[ -f "$detached_status" ]]; then
    break
  fi
  sleep 0.1
done
launchctl remove "$DETACHED_LABEL" >/dev/null 2>&1 || true
DETACHED_LABEL=""
if [[ ! -f "$detached_status" ]]; then
  echo 'BUG: detached replay attempt did not finish' >&2
  exit 1
fi
detached_rc="$(tr -d '[:space:]' < "$detached_status")"
if [[ "$detached_rc" == "0" ]]; then
  echo 'BUG: detached process-tree replay unexpectedly succeeded' >&2
  exit 1
fi
if grep -q 'UNEXPECTED_CHILD_STARTED' "$detached_output"; then
  echo 'BUG: detached process-tree replay spawned child' >&2
  exit 1
fi
echo 'detached process-tree replay rejected before child spawn'

missing_output="$workdir/missing-alias.out"
if run_with_session "$SESSION_TOKEN" \
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

run_with_session "$SESSION_TOKEN" \
  --only SESSION_E2E_CLI_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" cli
run_with_session "$SESSION_TOKEN" \
  --only SESSION_E2E_PROFILE_TOKEN,SESSION_E2E_CLI_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" both

agent-secret session list --json=compact |
  python3 -c 'import os, json, sys
session_id = sys.argv[1]
data = json.load(sys.stdin)
matches = [
    s for s in data["sessions"]
    if s["session_id"] == session_id
    and s["remaining_reads"] == 1 and s["secret_aliases"] == [
        "SESSION_E2E_CLI_TOKEN",
        "SESSION_E2E_PROFILE_TOKEN",
    ]
]
assert len(matches) >= 1, data
assert matches[0]["cwd"] == os.getcwd(), matches[0]
assert "session_token" not in matches[0], matches[0]
print("read count after subset runs ok")' "$SESSION_ID"

agent-secret session destroy "$SESSION_ID" >/dev/null
destroyed_output="$workdir/destroyed.out"
if run_with_session "$SESSION_TOKEN" \
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
SESSION_TOKEN=""

bind_name="$(basename "$(ps -p "$$" -o comm= | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')")"
if [ -z "$bind_name" ]; then
  echo 'failed to determine current shell process name for bind-ancestor-name' >&2
  exit 1
fi

EXHAUST_JSON="$(env -u SESSION_E2E_PROFILE_TOKEN -u SESSION_E2E_CLI_TOKEN \
  agent-secret session create \
    --json=compact \
    --profile session-e2e \
    --secret "SESSION_E2E_CLI_TOKEN=$cli_ref" \
    --bind-ancestor-name "$bind_name" \
    --max-reads 1)"
EXHAUST_ID="$(printf '%s' "$EXHAUST_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["session_id"])')"
EXHAUST_TOKEN="$(printf '%s' "$EXHAUST_JSON" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["session_token"])')"
printf 'created one-read session: %s\n' "$EXHAUST_ID"
agent-secret session list --json=compact |
  python3 -c 'import json, sys
session_id = sys.argv[1]
bind_name = sys.argv[2]
data = json.load(sys.stdin)
matches = [s for s in data["sessions"] if s["session_id"] == session_id]
assert len(matches) == 1, data
binding = matches[0]["session_binding"]
assert binding["mode"] == "ancestor_name", binding
assert binding["ancestor_name"] == bind_name, binding
assert binding["ancestor_depth"] >= 1, binding
print("ancestor-name binding metadata ok")' "$EXHAUST_ID" "$bind_name"
run_with_session "$EXHAUST_TOKEN" \
  --only SESSION_E2E_PROFILE_TOKEN \
  --allow-mutable-executable \
  -- python3 -c "$check_py" profile

exhausted_output="$workdir/exhausted.out"
if run_with_session "$EXHAUST_TOKEN" \
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
EXHAUST_TOKEN=""

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
created mixed config+CLI session: asid_...
session list and binding metadata ok
full ok
profile ok
detached process-tree replay rejected before child spawn
missing alias rejected before child spawn
cli ok
both ok
read count after subset runs ok
destroyed session rejected before child spawn
created one-read session: asid_...
ancestor-name binding metadata ok
profile ok
read exhaustion rejected before child spawn
audit metadata ok
session E2E ok
```

## Coverage

This E2E run proves:

- `session create` accepts secrets from a project config profile and CLI args.
- `session create` accepts `session.bind: parent` from profile config and
  explicit `--bind-ancestor-name NAME` from CLI flags.
- `session create`, `session list`, and JSON parsing work with
  `--json=compact`.
- `session list` shows public session IDs and working directories for active
  sessions without values or session tokens, and includes non-secret binding
  metadata for both parent and ancestor-name bindings.
- `with-session` injects the full approved bag when `--only` is omitted.
- `with-session --only` injects config-only, CLI-only, and combined subsets.
- `with-session` accepts session tokens from the same requester process tree
  that created the session.
- The same `session_token` is rejected before child spawn when a detached
  launchd job from a different requester process tree tries to replay it.
- Unknown aliases fail before the child process starts.
- `session destroy` prevents further resolution.
- Read exhaustion prevents further resolution.
- Session and command lifecycle audit metadata is written.
