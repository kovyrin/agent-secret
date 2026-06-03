#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  scripts/validate-utm-clean-install.sh --base-vm NAME --test-ref OP_REF [options]

Options:
  --base-vm NAME        UTM template VM to clone.
  --test-ref OP_REF     Test-only 1Password reference for the real smoke.
  --test-account NAME   Optional 1Password account selector for Agent Secret.
  --transport MODE      auto, utm, or ssh. Default: auto.
  --ssh-user USER       Guest macOS user for SSH transport.
  --ssh-host HOST       Guest host/IP for SSH transport.
  --ssh-port PORT       Guest SSH port. Default: 22.
  --ssh-gui-session     Launch the guest smoke inside the logged-in GUI session.
  --ssh-key PATH        SSH private key. Defaults to id_ed25519, then id_rsa.
  --clone-name NAME     Clone name. Defaults to agent-secret-validate-<time>.
  --existing-vm         Validate the already-running SSH target; skip UTM clone/start/cleanup.
  --report-dir DIR      Host report directory.
  --real-exec           Run one real approval-gated exec smoke.
  --cleanup             Stop and delete the clone after the run.
  --keep-clone          Keep the clone after the run. Default.
  --boot-timeout SEC    Guest startup timeout. Default: 300.
  --utmctl PATH         Path to utmctl.
  --print-bootstrap     Print one-time commands to run in the template VM.
  -h, --help            Show this help.

Environment defaults:
  AGENT_SECRET_UTM_BASE_VM
  AGENT_SECRET_TEST_REF
  AGENT_SECRET_TEST_ACCOUNT
  AGENT_SECRET_UTM_TRANSPORT
  AGENT_SECRET_UTM_SSH_USER
  AGENT_SECRET_UTM_SSH_HOST
  AGENT_SECRET_UTM_SSH_PORT
  AGENT_SECRET_UTM_SSH_GUI_SESSION=0
  AGENT_SECRET_UTM_SSH_KEY
  AGENT_SECRET_UTM_CLONE_NAME
  AGENT_SECRET_UTM_EXISTING_VM=0
  AGENT_SECRET_UTM_REPORT_DIR
  AGENT_SECRET_UTM_REAL_EXEC=0
  AGENT_SECRET_UTM_KEEP_CLONE=1
  AGENT_SECRET_UTM_BOOT_TIMEOUT
  AGENT_SECRET_UTMCTL
USAGE
}

fail() {
  printf 'validate-utm-clean-install: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '==> %s\n' "$*" >&2
}

timestamp="$(date +%Y%m%d-%H%M%S)"
default_ssh_key="$HOME/.ssh/id_ed25519"
if [ ! -f "$default_ssh_key" ] && [ -f "$HOME/.ssh/id_rsa" ]; then
  default_ssh_key="$HOME/.ssh/id_rsa"
fi
utmctl="${AGENT_SECRET_UTMCTL:-/Applications/UTM.app/Contents/MacOS/utmctl}"
base_vm="${AGENT_SECRET_UTM_BASE_VM:-}"
clone_name="${AGENT_SECRET_UTM_CLONE_NAME:-agent-secret-validate-$timestamp}"
existing_vm="${AGENT_SECRET_UTM_EXISTING_VM:-0}"
keep_clone="${AGENT_SECRET_UTM_KEEP_CLONE:-1}"
boot_timeout="${AGENT_SECRET_UTM_BOOT_TIMEOUT:-300}"
test_ref="${AGENT_SECRET_TEST_REF:-}"
test_account="${AGENT_SECRET_TEST_ACCOUNT:-}"
transport="${AGENT_SECRET_UTM_TRANSPORT:-auto}"
ssh_user="${AGENT_SECRET_UTM_SSH_USER:-}"
ssh_host="${AGENT_SECRET_UTM_SSH_HOST:-}"
ssh_port="${AGENT_SECRET_UTM_SSH_PORT:-22}"
ssh_gui_session="${AGENT_SECRET_UTM_SSH_GUI_SESSION:-${AGENT_SECRET_UTM_SSH_GUI_TERMINAL:-0}}"
ssh_key="${AGENT_SECRET_UTM_SSH_KEY:-$default_ssh_key}"
real_exec="${AGENT_SECRET_UTM_REAL_EXEC:-0}"
report_dir="${AGENT_SECRET_UTM_REPORT_DIR:-$project_root/_dist/vm-validation/$timestamp}"
print_bootstrap=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-vm)
      base_vm="${2:-}"
      shift 2
      ;;
    --test-ref)
      test_ref="${2:-}"
      shift 2
      ;;
    --test-account)
      test_account="${2:-}"
      shift 2
      ;;
    --transport)
      transport="${2:-}"
      shift 2
      ;;
    --ssh-user)
      ssh_user="${2:-}"
      shift 2
      ;;
    --ssh-host)
      ssh_host="${2:-}"
      shift 2
      ;;
    --ssh-port)
      ssh_port="${2:-}"
      shift 2
      ;;
    --ssh-gui-session | --ssh-gui-terminal)
      ssh_gui_session=1
      shift
      ;;
    --ssh-key)
      ssh_key="${2:-}"
      shift 2
      ;;
    --clone-name)
      clone_name="${2:-}"
      shift 2
      ;;
    --existing-vm)
      existing_vm=1
      shift
      ;;
    --report-dir)
      report_dir="${2:-}"
      shift 2
      ;;
    --real-exec)
      real_exec=1
      shift
      ;;
    --cleanup)
      keep_clone=0
      shift
      ;;
    --keep-clone)
      keep_clone=1
      shift
      ;;
    --boot-timeout)
      boot_timeout="${2:-}"
      shift 2
      ;;
    --utmctl)
      utmctl="${2:-}"
      shift 2
      ;;
    --print-bootstrap)
      print_bootstrap=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

if [ "$existing_vm" != "1" ]; then
  [ -x "$utmctl" ] || fail "utmctl not found or not executable: $utmctl"
fi
case "$transport" in
  auto | utm | ssh) ;;
  *) fail "--transport must be auto, utm, or ssh" ;;
esac
case "$boot_timeout" in
  '' | *[!0-9]*) fail "--boot-timeout must be an integer" ;;
esac
case "$ssh_port" in
  '' | *[!0-9]*) fail "--ssh-port must be an integer" ;;
esac

if [ "$print_bootstrap" = "1" ]; then
  pub_key="${AGENT_SECRET_UTM_SSH_PUBKEY:-}"
  if [ -z "$pub_key" ] && [ -f "$ssh_key.pub" ]; then
    pub_key="$(cat "$ssh_key.pub")"
  fi
  [ -n "$pub_key" ] || fail "no public key found; set AGENT_SECRET_UTM_SSH_PUBKEY or --ssh-key"

  cat <<BOOTSTRAP
# Run this once in Terminal inside the UTM template VM.
# It enables SSH transport for the host validation runner.

mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
cat >/tmp/agent-secret-validation-host-key.pub <<'AGENT_SECRET_VALIDATION_KEY'
$pub_key
AGENT_SECRET_VALIDATION_KEY
grep -qxF "\$(cat /tmp/agent-secret-validation-host-key.pub)" ~/.ssh/authorized_keys \\
  || cat /tmp/agent-secret-validation-host-key.pub >> ~/.ssh/authorized_keys
rm /tmp/agent-secret-validation-host-key.pub
sudo systemsetup -setremotelogin on
BOOTSTRAP
  exit 0
fi

if [ "$existing_vm" = "1" ]; then
  transport="ssh"
  clone_name="existing-vm"
  keep_clone=1
  [ -n "$ssh_host" ] || fail "--ssh-host is required with --existing-vm"
else
  [ -n "$base_vm" ] || fail "--base-vm or AGENT_SECRET_UTM_BASE_VM is required"
fi
[ -n "$test_ref" ] || fail "--test-ref or AGENT_SECRET_TEST_REF is required"

mkdir -p "$report_dir"
report_dir="$(cd -- "$report_dir" && pwd)"

created_clone=0
guest_status=0

cleanup() {
  if [ "$created_clone" != "1" ] || [ "$keep_clone" = "1" ]; then
    return
  fi

  log "stopping and deleting clone $clone_name"
  "$utmctl" stop --hide "$clone_name" --request >/dev/null 2>&1 ||
    "$utmctl" stop --hide "$clone_name" --force >/dev/null 2>&1 ||
    true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$("$utmctl" status "$clone_name" 2>/dev/null || true)" != "started" ]; then
      break
    fi
    "$utmctl" stop --hide "$clone_name" --force >/dev/null 2>&1 || true
    sleep 1
  done

  for _ in 1 2 3 4 5; do
    "$utmctl" delete --hide "$clone_name" >/dev/null 2>&1 || true
    if ! "$utmctl" list | awk 'NR > 1 { sub(/^[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, ""); print }' |
      grep -Fxq "$clone_name"; then
      break
    fi
    sleep 1
  done
}
trap cleanup EXIT

command_output_has_utm_guest_error() {
  case "$1" in
    *"Operation not supported by the backend."* | *"OSStatus error -2700"*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

wait_for_utm_guest() {
  local deadline
  local output
  local status
  deadline=$((SECONDS + boot_timeout))

  while [ "$SECONDS" -lt "$deadline" ]; do
    set +e
    output="$("$utmctl" exec --hide "$clone_name" --cmd /usr/bin/true 2>&1)"
    status=$?
    set -e
    printf '%s\n' "$output" >"$report_dir/utm-exec-probe.log"
    if command_output_has_utm_guest_error "$output"; then
      return 2
    fi
    if [ "$status" -eq 0 ]; then
      if [ -z "$output" ] || ! command_output_has_utm_guest_error "$output"; then
        return 0
      fi
    fi
    sleep 2
  done

  return 1
}

utm_guest_exec_supported() {
  local output
  local status

  set +e
  output="$("$utmctl" exec --hide "$clone_name" --cmd /usr/bin/true 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output" >"$report_dir/utm-exec-probe.log"

  if command_output_has_utm_guest_error "$output"; then
    return 1
  fi

  [ "$status" -eq 0 ] || return 0
}

normalize_mac() {
  printf '%s\n' "$1" |
    tr '[:upper:]' '[:lower:]' |
    sed -E 's/(^|:)0([0-9a-f])/\1\2/g'
}

discover_vm_package() {
  local utm_docs="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents"
  local candidate="$utm_docs/$clone_name.utm"

  [ -d "$candidate" ] || return 1
  printf '%s\n' "$candidate"
}

discover_ssh_host() {
  local vm_package
  local mac
  local normalized_mac

  if [ -n "$ssh_host" ]; then
    printf '%s\n' "$ssh_host"
    return 0
  fi

  vm_package="$(discover_vm_package)" || return 1
  mac="$(plutil -extract Network.0.MacAddress raw -o - "$vm_package/config.plist")"
  normalized_mac="$(normalize_mac "$mac")"

  arp -an |
    awk -v expected="$normalized_mac" '
			function normalize(mac, parts, i, out) {
				split(tolower(mac), parts, ":")
				out = ""
				for (i = 1; i <= 6; i++) {
					sub(/^0/, "", parts[i])
					out = out (i == 1 ? "" : ":") parts[i]
				}
				return out
			}
			normalize($4) == expected {
				gsub(/[()]/, "", $2)
				print $2
				exit
			}
		'
}

ssh_options() {
  printf '%s\n' \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=yes \
    -o "Port=$ssh_port" \
    -o "UserKnownHostsFile=$report_dir/ssh-known-hosts"
  if [ -n "$ssh_key" ] && [ -f "$ssh_key" ]; then
    printf '%s\n' -i "$ssh_key"
  fi
}

ensure_ssh_known_host() {
  local host="$1"
  local known_hosts="$report_dir/ssh-known-hosts"
  local lookup="$host"
  local scan_tmp

  if [ "$ssh_port" != "22" ]; then
    lookup="[$host]:$ssh_port"
  fi
  mkdir -p "$(dirname -- "$known_hosts")"
  touch "$known_hosts"
  chmod 600 "$known_hosts"
  if ssh-keygen -F "$lookup" -f "$known_hosts" >/dev/null 2>&1; then
    return
  fi

  log "bootstrapping SSH host key for $lookup"
  scan_tmp="$known_hosts.tmp.$$"
  if ! ssh-keyscan -p "$ssh_port" -T 10 "$host" >"$scan_tmp" 2>"$report_dir/ssh-keyscan.log"; then
    rm -f "$scan_tmp"
    fail "could not bootstrap SSH host key for $lookup; see $report_dir/ssh-keyscan.log"
  fi
  cat "$scan_tmp" >>"$known_hosts"
  rm -f "$scan_tmp"
}

ssh_target_for_host() {
  local host="$1"

  [ -n "$ssh_user" ] || fail "--ssh-user or AGENT_SECRET_UTM_SSH_USER is required for SSH transport"
  printf '%s@%s\n' "$ssh_user" "$host"
}

ssh_probe() {
  local host="$1"
  local target
  local opts

  target="$(ssh_target_for_host "$host")"
  ensure_ssh_known_host "$host"
  opts=()
  while IFS= read -r opt; do
    opts+=("$opt")
  done < <(ssh_options)
  ssh "${opts[@]}" "$target" /usr/bin/true >/dev/null 2>&1
}

wait_for_ssh() {
  local deadline
  local host
  deadline=$((SECONDS + boot_timeout))

  while [ "$SECONDS" -lt "$deadline" ]; do
    host="$(discover_ssh_host || true)"
    if [ -n "$host" ] && ssh_probe "$host"; then
      ssh_host="$host"
      printf '%s\n' "$host" >"$report_dir/ssh-host.txt"
      return 0
    fi
    sleep 3
  done

  return 1
}

shell_quote() {
  printf '%q' "$1"
}

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-secret-utm.XXXXXX")"
guest_script="$tmp_dir/agent-secret-vm-smoke.sh"
guest_runner="$tmp_dir/agent-secret-vm-smoke-runner.sh"

cleanup_tmp() {
  rm -rf "$tmp_dir"
}
trap 'cleanup; cleanup_tmp' EXIT

cat >"$guest_script" <<'GUEST_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
current_user="$(id -un)"
current_home="$(dscl . -read "/Users/$current_user" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')"
export USER="${USER:-$current_user}"
export LOGNAME="${LOGNAME:-$current_user}"
export HOME="${HOME:-${current_home:-/Users/$current_user}}"
export TMPDIR="${TMPDIR:-/tmp}"

guest_report_dir="/tmp/agent-secret-validation"
guest_archive="/tmp/agent-secret-validation.tgz"

fail() {
  printf 'agent-secret-vm-smoke: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '==> %s\n' "$*" >&2
}

run_logged() {
  local name="$1"
  shift
  log "$name"
  "$@" >"$guest_report_dir/$name.log" 2>&1
}

[ -n "${AGENT_SECRET_TEST_REF:-}" ] || fail "AGENT_SECRET_TEST_REF is required"

account_args=()
if [ -n "${AGENT_SECRET_TEST_ACCOUNT:-}" ]; then
  export AGENT_SECRET_1PASSWORD_ACCOUNT="$AGENT_SECRET_TEST_ACCOUNT"
  account_args=(--account "$AGENT_SECRET_TEST_ACCOUNT")
fi

rm -rf "$guest_report_dir" "$guest_archive"
mkdir -p "$guest_report_dir"

archive_report() {
  if [ -d "$guest_report_dir" ]; then
    tar -C /tmp -czf "$guest_archive" agent-secret-validation
  fi
}
trap archive_report EXIT

sw_vers >"$guest_report_dir/sw_vers.txt" 2>&1 || true
uname -a >"$guest_report_dir/uname.txt" 2>&1 || true
id >"$guest_report_dir/user.txt" 2>&1 || true

command -v brew >/dev/null 2>&1 || fail "Homebrew is not installed"
brew --version >"$guest_report_dir/brew-version.txt" 2>&1
brew list --cask --versions agent-secret \
  >"$guest_report_dir/brew-agent-secret-before.txt" 2>&1 || true

if command -v agent-secret >/dev/null 2>&1; then
  log "stopping existing Agent Secret daemon"
  agent-secret daemon stop --json >"$guest_report_dir/daemon-stop-before-uninstall.json" 2>&1 || true
fi

run_logged "brew-update" brew update

if ! brew tap | grep -qx 'kovyrin/agent-secret'; then
  run_logged "brew-tap-agent-secret" \
    brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
fi

run_logged "brew-uninstall-agent-secret" \
  brew uninstall --cask --force agent-secret || true

log "installing Agent Secret cask"
brew install --cask --force kovyrin/agent-secret/agent-secret \
  >"$guest_report_dir/brew-install-agent-secret.log" 2>&1

log "checking installed paths"
which -a agent-secret >"$guest_report_dir/which-agent-secret.txt" 2>&1

log "checking installed version"
agent-secret --version | tee "$guest_report_dir/agent-secret-version.txt"

log "resetting Agent Secret daemon after install"
agent-secret daemon stop --json >"$guest_report_dir/daemon-stop-after-install.json" 2>&1 || true

log "checking agent context"
agent-secret agent-context --json >"$guest_report_dir/agent-context.json"

log "installing bundled agent skill"
agent-secret skill-install --json | tee "$guest_report_dir/skill-install.json"

log "running doctor"
agent-secret doctor --json | tee "$guest_report_dir/doctor.json"

log "running dry-run request validation"
agent-secret exec \
  --dry-run \
  --json \
  "${account_args[@]}" \
  --reason "Clean macOS VM Agent Secret validation" \
  --secret "AGENT_SECRET_SMOKE_TOKEN=$AGENT_SECRET_TEST_REF" \
  -- /usr/bin/true | tee "$guest_report_dir/dry-run.json"

if [ "${AGENT_SECRET_UTM_REAL_EXEC:-0}" = "1" ]; then
  log "running real approval smoke"
  set +e
  agent-secret exec \
    "${account_args[@]}" \
    --reason "Clean macOS VM Agent Secret validation" \
    --secret "AGENT_SECRET_SMOKE_TOKEN=$AGENT_SECRET_TEST_REF" \
    -- /bin/sh -c 'test -n "${AGENT_SECRET_SMOKE_TOKEN:-}"' \
    >"$guest_report_dir/real-exec.log" 2>&1
  real_status=$?
  set -e
  printf '%s\n' "$real_status" >"$guest_report_dir/real-exec-status.txt"
  [ "$real_status" -eq 0 ] || fail "real approval smoke failed with status $real_status"
else
  printf 'skipped\n' >"$guest_report_dir/real-exec-status.txt"
fi

brew list --cask --versions agent-secret \
  >"$guest_report_dir/brew-agent-secret-after.txt" 2>&1 || true

archive_report
GUEST_SCRIPT

write_guest_runner() {
  cat >"$guest_runner" <<GUEST_RUNNER
#!/usr/bin/env bash
set -uo pipefail
export AGENT_SECRET_TEST_REF=$(shell_quote "$test_ref")
export AGENT_SECRET_UTM_REAL_EXEC=$(shell_quote "$real_exec")
export AGENT_SECRET_TEST_ACCOUNT=$(shell_quote "$test_account")
/tmp/agent-secret-vm-smoke.sh > /tmp/agent-secret-vm-smoke-terminal.log 2>&1
run_status=\$?
printf '%s\n' "\$run_status" > /tmp/agent-secret-vm-smoke-terminal.status
exit "\$run_status"
GUEST_RUNNER
}

run_guest_with_utm() {
  log "pushing guest smoke script with utmctl"
  "$utmctl" file push --hide "$clone_name" /tmp/agent-secret-vm-smoke.sh \
    <"$guest_script"

  log "making guest smoke script executable"
  "$utmctl" exec --hide "$clone_name" --cmd \
    /bin/chmod 700 /tmp/agent-secret-vm-smoke.sh

  log "running guest smoke script with utmctl"
  set +e
  "$utmctl" exec --hide "$clone_name" \
    --env "AGENT_SECRET_TEST_REF=$test_ref" \
    --env "AGENT_SECRET_UTM_REAL_EXEC=$real_exec" \
    --env "AGENT_SECRET_TEST_ACCOUNT=$test_account" \
    --cmd /tmp/agent-secret-vm-smoke.sh \
    2>&1 | tee "$report_dir/guest-output.log"
  guest_status=${PIPESTATUS[0]}
  set -e

  if command_output_has_utm_guest_error "$(cat "$report_dir/guest-output.log")"; then
    guest_status=70
  fi

  log "pulling guest evidence bundle"
  if "$utmctl" file pull --hide "$clone_name" /tmp/agent-secret-validation.tgz \
    >"$report_dir/agent-secret-validation.tgz"; then
    tar -xzf "$report_dir/agent-secret-validation.tgz" -C "$report_dir"
  else
    log "guest evidence bundle was not available"
  fi
}

run_guest_with_ssh() {
  local target
  local opts
  local remote_cmd
  local deadline

  log "waiting for SSH"
  wait_for_ssh || fail "SSH did not become ready within ${boot_timeout}s; log into the VM and confirm Remote Login is enabled"

  target="$(ssh_target_for_host "$ssh_host")"
  opts=()
  while IFS= read -r opt; do
    opts+=("$opt")
  done < <(ssh_options)

  log "copying guest smoke script with scp"
  scp "${opts[@]}" "$guest_script" "$target:/tmp/agent-secret-vm-smoke.sh" \
    >"$report_dir/scp-push.log" 2>&1

  write_guest_runner
  scp "${opts[@]}" "$guest_runner" "$target:/tmp/agent-secret-vm-smoke-runner.sh" \
    >>"$report_dir/scp-push.log" 2>&1
  if [ "$ssh_gui_session" = "1" ]; then
    scp "${opts[@]}" "$guest_runner" \
      "$target:/tmp/agent-secret-vm-smoke.command" \
      >>"$report_dir/scp-push.log" 2>&1
  fi

  log "making guest smoke script executable"
  ssh "${opts[@]}" "$target" /bin/chmod 700 \
    /tmp/agent-secret-vm-smoke.sh /tmp/agent-secret-vm-smoke-runner.sh
  if [ "$ssh_gui_session" = "1" ]; then
    ssh "${opts[@]}" "$target" /bin/chmod 700 \
      /tmp/agent-secret-vm-smoke.command
  fi

  ssh "${opts[@]}" "$target" /bin/rm -f \
    /tmp/agent-secret-vm-smoke-terminal.status \
    /tmp/agent-secret-vm-smoke-terminal.log

  if [ "$ssh_gui_session" = "1" ]; then
    log "running guest smoke script in the logged-in Terminal session"
    set +e
    ssh "${opts[@]}" "$target" /usr/bin/open -a Terminal \
      /tmp/agent-secret-vm-smoke.command \
      >"$report_dir/guest-gui-launch.log" 2>&1
    launch_status=$?
    set -e
    if [ "$launch_status" -ne 0 ]; then
      guest_status=$launch_status
    fi
    deadline=$((SECONDS + boot_timeout))
    if [ "$guest_status" -eq 0 ]; then
      while [ "$SECONDS" -lt "$deadline" ]; do
        if ssh "${opts[@]}" "$target" /bin/test -f \
          /tmp/agent-secret-vm-smoke-terminal.status; then
          break
        fi
        sleep 3
      done

      if ! ssh "${opts[@]}" "$target" /bin/test -f \
        /tmp/agent-secret-vm-smoke-terminal.status; then
        guest_status=124
      else
        guest_status="$(ssh "${opts[@]}" "$target" /bin/cat \
          /tmp/agent-secret-vm-smoke-terminal.status)"
      fi
    fi
    ssh "${opts[@]}" "$target" /bin/cat /tmp/agent-secret-vm-smoke-terminal.log \
      >"$report_dir/guest-output.log" 2>&1 || true
    if [ "$guest_status" -eq 124 ]; then
      ssh "${opts[@]}" "$target" /usr/bin/pkill -f \
        /tmp/agent-secret-vm-smoke >/dev/null 2>&1 || true
    fi
  else
    remote_cmd="AGENT_SECRET_TEST_REF=$(shell_quote "$test_ref") "
    remote_cmd+="AGENT_SECRET_UTM_REAL_EXEC=$(shell_quote "$real_exec") "
    remote_cmd+="AGENT_SECRET_TEST_ACCOUNT=$(shell_quote "$test_account") "
    remote_cmd+="/tmp/agent-secret-vm-smoke.sh"

    log "running guest smoke script with SSH"
    set +e
    # shellcheck disable=SC2029
    ssh "${opts[@]}" "$target" "$remote_cmd" \
      2>&1 | tee "$report_dir/guest-output.log"
    guest_status=${PIPESTATUS[0]}
    set -e
  fi

  log "pulling guest evidence bundle"
  if scp "${opts[@]}" "$target:/tmp/agent-secret-validation.tgz" \
    "$report_dir/agent-secret-validation.tgz" >"$report_dir/scp-pull.log" 2>&1; then
    tar -xzf "$report_dir/agent-secret-validation.tgz" -C "$report_dir"
  else
    log "guest evidence bundle was not available"
  fi
}

printf 'base_vm=%s\nclone_name=%s\nexisting_vm=%s\nreal_exec=%s\ntransport=%s\nssh_port=%s\n' \
  "$base_vm" "$clone_name" "$existing_vm" "$real_exec" "$transport" "$ssh_port" >"$report_dir/host-summary.env"

selected_transport="$transport"
if [ "$existing_vm" != "1" ]; then
  "$utmctl" list >"$report_dir/utm-list-before.txt"

  log "cloning $base_vm to $clone_name"
  "$utmctl" clone --hide "$base_vm" --name "$clone_name" \
    2>&1 | tee "$report_dir/utm-clone.log"
  created_clone=1

  log "starting $clone_name"
  "$utmctl" start --hide "$clone_name" 2>&1 | tee "$report_dir/utm-start.log"

  if [ "$selected_transport" = "auto" ]; then
    if utm_guest_exec_supported; then
      selected_transport="utm"
    else
      selected_transport="ssh"
    fi
  fi
fi
printf '%s\n' "$selected_transport" >"$report_dir/transport.txt"

case "$selected_transport" in
  utm) run_guest_with_utm ;;
  ssh) run_guest_with_ssh ;;
esac

if [ "$existing_vm" != "1" ]; then
  "$utmctl" status "$clone_name" >"$report_dir/utm-status-after.txt" 2>&1 || true
fi
printf '%s\n' "$guest_status" >"$report_dir/guest-status.txt"

[ "$guest_status" -eq 0 ] || fail "guest validation failed; see $report_dir"

log "validation finished on $clone_name"
log "report written to $report_dir"
if [ "$existing_vm" != "1" ] && [ "$keep_clone" = "1" ]; then
  log "clone kept for inspection; pass --cleanup to delete it after the run"
fi
