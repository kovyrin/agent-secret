package cli

import "strings"

func TopHelp() string {
	return strings.TrimSpace(`
agent-secret controls short-lived local access to 1Password-backed secrets for coding agents.

Secrets are never printed by agent-secret and are never written to disk. The normal path is:

  1. agent-secret validates the command, reason, cwd, TTL, and exact secret refs.
  2. agent-secret starts or connects to the per-user daemon.
  3. The daemon asks the native macOS approver before any 1Password access.
  4. If approved, the daemon fetches exactly the approved refs and sends an env payload to agent-secret exec.
  5. agent-secret exec spawns the child process and passes stdin/stdout/stderr through unchanged.

Commands:

  exec       Run a command with approved secrets injected as environment variables.
  item       Inspect 1Password item metadata without revealing secret values.
  install-cli Install or repair the agent-secret command symlink for this user.
  skill-install Install or repair the Agent Secret agent skill for this user.
  daemon    Troubleshoot the hidden per-user daemon: status, start, stop.
  doctor    Print non-secret local diagnostics for setup troubleshooting.
  version   Print the installed agent-secret version.
  help      Show this help.

Common examples:

  agent-secret exec --reason "Terraform plan for previews" \
    --secret CLOUDFLARE_API_TOKEN=op://Example/Cloudflare/token \
    -- terraform plan

  agent-secret exec -- terraform plan

  agent-secret exec --profile terraform-cloudflare -- terraform plan

  agent-secret exec --reason "Run Ansible against home inventory" \
    --cwd /path/to/project \
    --secret ANSIBLE_VAULT_PASSWORD=op://Example/Ansible/password \
    -- ansible-playbook site.yml

  agent-secret exec --reason "Run dotenv-based deploy" \
    --env-file .env \
    -- npm run deploy

  agent-secret exec --reason "Use a deliberate shell wrapper" \
    --secret TOKEN=op://Example/Item/token \
    -- sh -c 'echo "$TOKEN" >/dev/null'

  agent-secret item describe "op://Example/Cloudflare Token"
  agent-secret item describe --format env-refs --prefix CLOUDFLARE "op://Example/Cloudflare Token"

Safety rules:

  - --reason is required, trimmed, and capped at 240 characters.
  - --secret must be ALIAS=op://vault/item[/section]/field-or-text-file.
  - --profile NAME loads refs and defaults from agent-secret.yml or .agent-secret.yml in the current directory or a parent.
  - If no --profile, --secret, or --env-file is provided, exec uses default_profile from the discovered project config.
  - --env-file PATH loads dotenv-style KEY=VALUE entries. op:// values become approved secret refs; other values are passed only to the child.
  - --only filters profile refs and env-file refs, but not deliberate one-off --secret refs.
  - Project configs can set account defaults at the file, profile, or secret level, and profiles may include other profiles.
  - --account sets a default 1Password account for CLI-provided refs when config does not already provide one.
  - ALIAS must look like an environment variable name, for example API_TOKEN.
  - With no account override, agent-secret detects one signed-in 1Password CLI account before falling back to my.1password.com.
  - The wrapped command must appear after -- as argv. agent-secret does not parse shell strings.
  - exec has no --json mode and never prints secret values.
  - Text file/document refs such as op://Example/GitHub App/key.pem are injected as env values; binary attachments are not supported.
  - item describe requires approval and prints item metadata only: field labels, types, concealment flags, and refs.
  - agent-secret skill-install links the bundled Agent Secret skill into ~/.agents/skills/agent-secret.
  - Reusable approval is selected only in the approval UI, not by a CLI flag.
  - Audit metadata is written to ~/Library/Logs/agent-secret/audit.jsonl.
  - Non-zero child exits are returned as child exits, not as broker failures.

Run agent-secret exec --help for flags and more examples.
`)
}

func ItemHelp() string {
	return strings.TrimSpace(`
agent-secret item provides secret-safe inspection commands for 1Password items.

Commands:

  describe  Show approved item metadata without revealing secret values.

Run agent-secret item describe --help for flags and examples.
`)
}

func ItemDescribeHelp() string {
	return strings.TrimSpace(`
agent-secret item describe asks the local approver for permission to inspect one 1Password item, then prints metadata only.

Usage:

  agent-secret item describe [flags] op://vault/item
  agent-secret item describe [flags] op://vault/item/*

Flags:

  --account ACCOUNT   1Password account override. Defaults to project config, environment, one detected CLI account, then my.1password.com.
  --config PATH       Profile config path. Defaults to upward discovery from the current directory.
  --format FORMAT     Output format: text, json, or env-refs. Defaults to text.
  --prefix PREFIX     Prefix env aliases in env-refs output.
  --reason TEXT       Human-readable reason shown to the approver. Defaults to item metadata inspection.
  --ttl DURATION      Approval TTL. Defaults to 2m. Allowed range: 10s through 10m.
  -h, --help          Show this help.

Output never includes field values. It may include item title, field labels, field ids, field types, section names, concealment flags, accounts, and canonical op:// refs.

Examples:

  agent-secret item describe "op://Fixture Infra/Beta PlanetScale Introspection Probe"
  agent-secret item describe --format env-refs --prefix PLANETSCALE "op://Fixture Infra/Beta PlanetScale Introspection Probe"
  agent-secret item describe --format json "op://Fixture Infra/Beta PlanetScale Introspection Probe/*"
`)
}

func ExecHelp() string {
	return strings.TrimSpace(`
agent-secret exec validates a command request, asks the local daemon for approved secrets, and then runs the wrapped command.

Usage:

  agent-secret exec --reason TEXT --secret ALIAS=op://vault/item/field-or-text-file [flags] -- COMMAND [ARG...]
  agent-secret exec --profile NAME [flags] -- COMMAND [ARG...]
  agent-secret exec --reason TEXT --env-file PATH [flags] -- COMMAND [ARG...]

Required:

  --reason TEXT       Human-readable reason shown to the approver and used for reuse matching. Required unless the profile sets reason.
  --secret MAPPING    Secret alias mapping. Repeat for multiple refs. Format: ALIAS=op://vault/item[/section]/field-or-text-file. Required unless a profile, default_profile, or --env-file supplies secret refs.
  -- COMMAND [ARG...] Command argv to execute. The -- boundary is required.

Flags:

  --profile NAME      Load a named profile from agent-secret.yml or .agent-secret.yml in the current directory or a parent.
  --only ALIAS        Keep only selected profile/env-file aliases. Repeat or pass comma-separated aliases.
  --env-file PATH     Load dotenv-style entries. Repeat for multiple files; later files win.
  --account ACCOUNT   Default 1Password account when config does not provide one.
  --config PATH       Profile config path. Defaults to upward discovery from the current directory.
  --cwd DIR           Child working directory. Defaults to the caller cwd.
  --ttl DURATION      Approval TTL. Defaults to profile ttl or 2m. Allowed range: 10s through 10m.
  --override-env      Allow approved aliases to replace existing child environment variables.
  --force-refresh     For matching reusable approvals, refetch approved refs before delivery.
  -h, --help          Show this help.

Project profiles:

  Put agent-secret.yml or .agent-secret.yml at the project root:

    version: 1
    account: my.1password.com
    default_profile: terraform-cloudflare
    profiles:
      terraform-cloudflare:
        account: Fixture
        reason: Terraform DNS management
        ttl: 10m
        secrets:
          CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
          PREVIEW_TOKEN:
            ref: op://Example/Preview/token
            account: Fixture Preview
          SHARED_TOKEN: op://Example/Shared/token

      ansible:
        include:
          - terraform-cloudflare
        reason: Run Ansible playbook
        secrets:
          ANSIBLE_BECOME_PASSWORD: op://Example/Ansible/password

  Then run:

    agent-secret exec -- terraform plan
    agent-secret exec --profile terraform-cloudflare -- terraform plan
    agent-secret exec --profile ansible --only CADDY_TOKEN,POSTGRES_PASSWORD -- ansible-playbook site.yml

  --secret flags may be combined with --profile for one-off additional refs.
  --env-file may be combined with --profile or --secret. Values that start with
  op:// are treated as secret refs; other values are passed to the child as
  plain environment entries. When multiple env files define the same key, the
  later file wins. Env-file keys override the caller environment for that child.
  --account applies when a loaded profile, config, or explicit secret entry does
  not already supply an account default.
  --only filters profile-loaded aliases and env-file secret aliases before
  one-off --secret refs are added.
  Invocations with explicit --secret or --env-file sources do not load
  default_profile unless --profile is provided.
  CLI --reason and --ttl override profile defaults.
  Account precedence is per-secret account, profile account, top-level account,
  --account, OP_ACCOUNT / AGENT_SECRET_1PASSWORD_ACCOUNT, one detected signed-in
  1Password CLI account, then my.1password.com.
  Included profiles are resolved in order. Later includes and the selected
  profile override earlier secrets with the same alias.
  1Password text file/document refs are resolved into the alias env value with
  multiline text preserved. Binary attachments are not supported by env-var
  delivery.

Environment:

  OP_ACCOUNT                      Optional 1Password account sign-in address, name, or UUID override.
  AGENT_SECRET_1PASSWORD_ACCOUNT  Optional 1Password account sign-in address, name, or UUID override. Empty uses OP_ACCOUNT, then detection.

Default account:

  When no override is set, agent-secret uses the single signed-in 1Password CLI
  account when one can be detected, then falls back to my.1password.com.

Unsupported by design:

  --json              exec passes stdin/stdout/stderr through unchanged and has no JSON mode.
  --reuse             The approver decides whether an approval is reusable.

Examples:

  agent-secret exec --reason "Terraform plan" \
    --secret CLOUDFLARE_TOKEN=op://Example/Cloudflare/token \
    -- terraform plan

  agent-secret exec --reason "Refresh preview DNS" \
    --cwd /path/to/infra \
    --ttl 90s \
    --force-refresh \
    --secret DNS_TOKEN=op://Example/DNS/token \
    -- sh -c 'terraform plan && terraform apply'

Exit behavior:

  If approval, audit, daemon connection, or secret fetch fails before payload delivery, the child is not spawned.
  After the child starts, stdin, stdout, and stderr are passed through. The wrapper returns the child exit status.
  Audit metadata is written to ~/Library/Logs/agent-secret/audit.jsonl.
`)
}

func DaemonHelp() string {
	return strings.TrimSpace(`
agent-secret daemon is for troubleshooting the hidden per-user daemon.

Usage:

  agent-secret daemon status
  agent-secret daemon start
  agent-secret daemon stop

Normal agent-secret exec use starts the daemon automatically and does not print daemon lifecycle details unless something fails.
Daemon stop clears daemon-owned in-memory reusable approvals, use counters, nonces, and cached values. It does not signal or manage already-running child processes.
`)
}

func DoctorHelp() string {
	return strings.TrimSpace(`
agent-secret doctor starts the daemon if needed and prints non-secret local diagnostics: platform, socket directory privacy, audit log writability, daemon status, native approver health, and 1Password desktop integration readiness.
It never prints secret values or resolves 1Password item references.
`)
}

func InstallCLIHelp() string {
	return strings.TrimSpace(`
agent-secret install-cli installs or repairs the command-line entry point for the current user.

Usage:

  agent-secret install-cli [--bin-dir DIR] [--force]

The command creates:

  ~/.local/bin/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/bin/agent-secret

On a clean macOS shell, ~/.local/bin is usually not on PATH. If install-cli
prints a PATH warning, paste the shown one-liner into Terminal.

When run from a development or test build, it links to the executable that is
currently running. If the command is already a symlink to that executable, it is
left in place. Existing regular files and symlinks to different targets are not
replaced unless --force is passed. Directories are always refused.

Flags:

  --bin-dir DIR  Directory that should contain the agent-secret command. Defaults to ~/.local/bin.
  --force        Replace an existing regular file or different symlink at DIR/agent-secret.
`)
}

func SkillInstallHelp() string {
	return strings.TrimSpace(`
agent-secret skill-install installs or repairs the Agent Secret coding-agent skill for the current user.

Usage:

  agent-secret skill-install [--skills-dir DIR] [--force]

The command creates:

  ~/.agents/skills/agent-secret -> /Applications/Agent Secret.app/Contents/Resources/skills/agent-secret

The skill covers general Agent Secret usage, project profiles, env-file usage,
safe verification, and migration from direct 1Password CLI access. When run
from a development or test build, it links to the bundled skill next to the
currently running agent-secret executable.
If the skill is already a symlink to that target, it is left in place. Existing
regular files and symlinks to different targets are not replaced unless --force
is passed. Directories are always refused.

Flags:

  --skills-dir DIR  Directory that should contain the agent-secret skill. Defaults to ~/.agents/skills.
  --force           Replace an existing regular file or different symlink at DIR/agent-secret.
`)
}
