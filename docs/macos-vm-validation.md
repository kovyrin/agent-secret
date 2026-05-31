# macOS VM Validation

Use this drill before public release announcements and after release packaging
changes. It validates the installed Homebrew cask against a clean macOS user
environment with a dedicated 1Password guest account and test-only vault.

## Scope

This is an opt-in live validation. It intentionally exercises real macOS,
1Password Desktop integration, the native approval UI, and one approved child
process. It must never use production 1Password accounts or real secrets.

The drill validates:

- Homebrew tap and cask installation.
- Installed CLI version and bundle path.
- `agent-secret skill-install`.
- `agent-secret doctor --json`.
- Dry-run request validation without prompting or secret resolution.
- One real approval that injects a test-only value into a child process without
  printing it.

## Golden VM Setup

Create one stopped UTM VM that acts as the reusable base image.

1. Complete macOS first-run setup.
2. Create a local test user.
3. Install Homebrew.
4. Install 1Password Desktop.
5. Sign in with a dedicated 1Password guest account, not a maintainer account.
6. Give that guest account access to exactly one test vault.
7. Enable 1Password SDK integration in 1Password Desktop:
   `Settings -> Developer -> Integrate with the 1Password SDKs -> Integrate
   with other apps`.
8. Add one low-risk test secret to the test vault.
9. Enable SSH transport for the validation runner.

   Apple-backed macOS VMs do not support UTM's guest command/file APIs, so the
   runner uses SSH for command execution and evidence collection. From the host,
   print the bootstrap commands:

   ```bash
   scripts/validate-utm-clean-install.sh --print-bootstrap
   ```

   Run the printed commands once in Terminal inside the template VM. They add
   the host public key to `~/.ssh/authorized_keys` and enable Remote Login.

10. Keep the template logged into the macOS desktop, or configure automatic
    login for the dedicated test user. The native Agent Secret approval UI and
    1Password Desktop integration need a GUI user session.

Stop the VM cleanly when setup is complete. Do not run validation directly
against a base VM unless UTM disposable mode is enabled or the VM has been
cloned first.

## Host Runner

Run the host-side validation script from this repository:

```bash
scripts/validate-utm-clean-install.sh \
  --base-vm 'macOS with 1Password Template' \
  --ssh-user agentsecret \
  --test-ref 'op://Example/Agent Secret Smoke/password'
```

Use the real test-only `op://` reference for `AGENT_SECRET_TEST_REF` when
running the drill. The script passes the reference to Agent Secret but never
prints the resolved value.

By default, the script creates a clone, starts it, runs the non-secret checks,
pulls a report bundle into `_dist/vm-validation/`, and keeps the clone for
inspection. Pass `--cleanup` to stop and delete the clone after the run.

The real approval step is opt-in because it requires the VM to be unlocked and
available for the human approval prompt. When using SSH transport, pass
`--ssh-gui-session` so the smoke script runs from the logged-in VM
Terminal.app session instead of a headless SSH process:

```bash
scripts/validate-utm-clean-install.sh \
  --base-vm 'macOS with 1Password Template' \
  --ssh-user agentsecret \
  --test-ref 'op://Example/Agent Secret Smoke/password' \
  --ssh-gui-session \
  --real-exec
```

The real step runs a child process that checks the injected environment
variable exists. It does not print the value.

For unattended post-run cleanup:

```bash
scripts/validate-utm-clean-install.sh \
  --base-vm 'macOS with 1Password Template' \
  --ssh-user agentsecret \
  --test-ref 'op://Example/Agent Secret Smoke/password' \
  --ssh-gui-session \
  --real-exec \
  --cleanup
```

For a VM that is already running and reachable over SSH, use SSH-only mode:

```bash
scripts/validate-utm-clean-install.sh \
  --existing-vm \
  --ssh-user agent-secret \
  --ssh-host 192.168.11.10 \
  --test-account support@agent-secret.sh \
  --test-ref 'op://Agent Secret Integration/Test Secret/password' \
  --ssh-gui-session \
  --real-exec
```

This mode skips UTM clone/start/cleanup and validates the cask, bundled skill,
doctor output, dry-run validation, and real approval smoke on the existing VM.
Use it when validating VM account setup or when macOS has not yet granted the
host automation process access to UTM lifecycle events. Keep 1Password unlocked
in the VM before starting this run, and approve the 1Password SDK authorization
or Agent Secret approval prompt if either appears.

## Evidence To Record

Record these results in the launch tracker or release issue:

- Agent Secret version reported by the VM.
- `agent-secret doctor --json` result.
- Dry-run JSON result with no secret value.
- Whether the real approval prompt appeared.
- Whether the real child-process smoke exited successfully.
- Any UI, signing, or 1Password Desktop authorization issue observed.
- Report directory path under `_dist/vm-validation/`.

## Troubleshooting

If SSH does not become ready, log into the VM and confirm Remote Login is
enabled. If the runner cannot discover the VM address from the UTM shared
network ARP table, pass `--ssh-host <ip-or-hostname>`.

If 1Password authorization fails, unlock 1Password Desktop in the VM, confirm
SDK integration is enabled, and verify the guest account can see only the test
vault.

If Homebrew reports an existing Agent Secret install, rebuild the golden VM or
run the drill from a fresh clone. The goal is to validate the install path from
the published cask, not a stale local app.
