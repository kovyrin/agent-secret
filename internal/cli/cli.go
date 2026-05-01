package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/profileconfig"
	"github.com/kovyrin/agent-secret/internal/request"
)

var (
	ErrHelpRequested       = errors.New("help requested")
	ErrInvalidArguments    = errors.New("invalid arguments")
	ErrUnsupportedExecJSON = errors.New("exec does not support json output")
	ErrUnsupportedReuse    = errors.New("reusable approvals are chosen in the approver")
	ErrShellStringCommand  = errors.New("command must be argv after --")
)

type Kind string

const (
	KindHelp         Kind = "help"
	KindExec         Kind = "exec"
	KindDoctor       Kind = "doctor"
	KindDaemonStart  Kind = "daemon_start"
	KindDaemonStop   Kind = "daemon_stop"
	KindDaemonStatus Kind = "daemon_status"
)

type Command struct {
	Kind        Kind
	ExecRequest request.ExecRequest
	HelpText    string
}

type Parser struct {
	now func() time.Time
}

func NewParser(now func() time.Time) Parser {
	if now == nil {
		now = time.Now
	}
	return Parser{now: now}
}

func (p Parser) Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{Kind: KindHelp, HelpText: TopHelp()}, ErrHelpRequested
	}

	switch args[0] {
	case "-h", "--help", "help":
		return Command{Kind: KindHelp, HelpText: TopHelp()}, ErrHelpRequested
	case "exec":
		return p.parseExec(args[1:])
	case "daemon":
		return parseDaemon(args[1:])
	case "doctor":
		return parseDoctor(args[1:])
	default:
		return Command{}, fmt.Errorf("%w: unknown command %q", ErrInvalidArguments, args[0])
	}
}

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
  daemon    Troubleshoot the hidden per-user daemon: status, start, stop.
  doctor    Print non-secret local diagnostics for setup troubleshooting.
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

  agent-secret exec --reason "Use a deliberate shell wrapper" \
    --secret TOKEN=op://Example/Item/token \
    -- sh -c 'echo "$TOKEN" >/dev/null'

Safety rules:

  - --reason is required, trimmed, and capped at 240 characters.
  - --secret must be ALIAS=op://vault/item[/section]/field.
  - --profile NAME loads refs and defaults from agent-secret.yml or .agent-secret.yml in the current directory or a parent.
  - If no --profile or --secret is provided, exec uses default_profile from the discovered project config.
  - Project configs can set account defaults at the file, profile, or secret level, and profiles may include other profiles.
  - ALIAS must look like an environment variable name, for example API_TOKEN.
  - By default, the daemon uses the personal 1Password sign-in address my.1password.com. Set AGENT_SECRET_1PASSWORD_ACCOUNT only to override it.
  - The wrapped command must appear after -- as argv. agent-secret does not parse shell strings.
  - exec has no --json mode and never prints secret values.
  - Reusable approval is selected only in the approval UI, not by a CLI flag.
  - Audit metadata is written to ~/Library/Logs/agent-secret/audit.jsonl.
  - Non-zero child exits are returned as child exits, not as broker failures.

Run agent-secret exec --help for flags and more examples.
`)
}

func ExecHelp() string {
	return strings.TrimSpace(`
agent-secret exec validates a command request, asks the local daemon for approved secrets, and then runs the wrapped command.

Usage:

  agent-secret exec --reason TEXT --secret ALIAS=op://vault/item/field [flags] -- COMMAND [ARG...]
  agent-secret exec --profile NAME [flags] -- COMMAND [ARG...]

Required:

  --reason TEXT       Human-readable reason shown to the approver and used for reuse matching. Required unless the profile sets reason.
  --secret MAPPING    Secret alias mapping. Repeat for multiple refs. Format: ALIAS=op://vault/item[/section]/field. Required unless a profile supplies secrets or the project config sets default_profile.
  -- COMMAND [ARG...] Command argv to execute. The -- boundary is required.

Flags:

  --profile NAME      Load a named profile from agent-secret.yml or .agent-secret.yml in the current directory or a parent.
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

  --secret flags may be combined with --profile for one-off additional refs.
  Explicit --secret-only invocations do not load default_profile.
  CLI --reason and --ttl override profile defaults.
  Account precedence is per-secret account, profile account, top-level account,
  OP_ACCOUNT / AGENT_SECRET_1PASSWORD_ACCOUNT, then my.1password.com.
  Included profiles are resolved in order. Later includes and the selected
  profile override earlier secrets with the same alias.

Environment:

  OP_ACCOUNT                      Optional 1Password account sign-in address, name, or UUID override.
  AGENT_SECRET_1PASSWORD_ACCOUNT  Optional 1Password account sign-in address, name, or UUID override. Empty uses OP_ACCOUNT or my.1password.com.

Default account:

  When no override is set, agent-secret asks 1Password Desktop for my.1password.com.

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

func (p Parser) parseExec(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: exec requires flags and -- command", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: ExecHelp()}, ErrHelpRequested
	}

	boundary := indexOf(args, "--")
	if boundary < 0 {
		return Command{}, ErrShellStringCommand
	}
	command := args[boundary+1:]
	if len(command) == 0 {
		return Command{}, ErrShellStringCommand
	}

	var secrets secretFlags
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "approval reason")
	cwd := fs.String("cwd", "", "working directory")
	ttl := fs.Duration("ttl", 0, "approval ttl")
	profileName := fs.String("profile", "", "profile name")
	configPath := fs.String("config", "", "profile config path")
	overrideEnv := fs.Bool("override-env", false, "override existing env aliases")
	forceRefresh := fs.Bool("force-refresh", false, "refresh reusable approval values")
	jsonOutput := fs.Bool("json", false, "unsupported")
	reuse := fs.Bool("reuse", false, "unsupported")
	fs.Var(&secrets, "secret", "secret mapping")
	if err := fs.Parse(args[:boundary]); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if *jsonOutput {
		return Command{}, ErrUnsupportedExecJSON
	}
	if *reuse {
		return Command{}, ErrUnsupportedReuse
	}
	if fs.NArg() != 0 {
		return Command{}, ErrShellStringCommand
	}
	effectiveReason := *reason
	effectiveTTL := *ttl
	effectiveSecrets := secrets.specs
	profile, loadedProfile, err := loadExecProfile(*profileName, *configPath, effectiveSecrets)
	if err != nil {
		return Command{}, err
	}
	if loadedProfile && effectiveReason == "" {
		effectiveReason = profile.Reason
	}
	if loadedProfile && effectiveTTL == 0 {
		effectiveTTL = profile.TTL
	}
	if loadedProfile {
		profileSecrets := slices.Clone(profile.Secrets)
		profileSecrets = append(profileSecrets, applyDefaultAccount(effectiveSecrets, profile.Account)...)
		effectiveSecrets = profileSecrets
	}

	req, err := request.NewExec(request.ExecOptions{
		Reason:       effectiveReason,
		Command:      command,
		CWD:          *cwd,
		Secrets:      effectiveSecrets,
		TTL:          effectiveTTL,
		ReceivedAt:   p.now(),
		DeliveryMode: request.DeliveryEnvExec,
		OverrideEnv:  *overrideEnv,
		ForceRefresh: *forceRefresh,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build exec request: %w", err)
	}

	return Command{Kind: KindExec, ExecRequest: req}, nil
}

func loadExecProfile(profileName string, configPath string, explicitSecrets []request.SecretSpec) (profileconfig.Profile, bool, error) {
	if profileName == "" && len(explicitSecrets) > 0 {
		return profileconfig.Profile{}, false, nil
	}

	profile, err := profileconfig.Load(profileconfig.LoadOptions{
		Name:       profileName,
		ConfigPath: configPath,
	})
	if err == nil {
		return profile, true, nil
	}
	if profileName == "" && configPath == "" && errors.Is(err, profileconfig.ErrConfigNotFound) {
		return profileconfig.Profile{}, false, nil
	}

	label := profileName
	if label == "" {
		label = "default"
	}
	return profileconfig.Profile{}, false, fmt.Errorf("load profile %q: %w", label, err)
}

func applyDefaultAccount(secrets []request.SecretSpec, account string) []request.SecretSpec {
	if account == "" || len(secrets) == 0 {
		return secrets
	}
	updated := make([]request.SecretSpec, 0, len(secrets))
	for _, secret := range secrets {
		if secret.Account == "" {
			secret.Account = account
		}
		updated = append(updated, secret)
	}
	return updated
}

func parseDaemon(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: daemon requires status, start, or stop", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: DaemonHelp()}, ErrHelpRequested
	}
	if len(args) != 1 {
		return Command{}, fmt.Errorf("%w: daemon accepts exactly one subcommand", ErrInvalidArguments)
	}
	switch args[0] {
	case "status":
		return Command{Kind: KindDaemonStatus}, nil
	case "start":
		return Command{Kind: KindDaemonStart}, nil
	case "stop":
		return Command{Kind: KindDaemonStop}, nil
	default:
		return Command{}, fmt.Errorf("%w: unknown daemon subcommand %q", ErrInvalidArguments, args[0])
	}
}

func parseDoctor(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: DoctorHelp()}, ErrHelpRequested
	}
	if len(args) != 0 {
		return Command{}, fmt.Errorf("%w: doctor accepts no arguments", ErrInvalidArguments)
	}
	return Command{Kind: KindDoctor}, nil
}

func DaemonHelp() string {
	return strings.TrimSpace(`
agent-secret daemon is for troubleshooting the hidden per-user daemon.

Usage:

  agent-secret daemon status
  agent-secret daemon start
  agent-secret daemon stop

Normal agent-secret exec use starts the daemon automatically and does not print daemon lifecycle details unless something fails.
Daemon stop clears daemon-owned in-memory approvals, sessions, counters, nonces, and cached values. It does not signal or manage already-running child processes.
`)
}

func DoctorHelp() string {
	return strings.TrimSpace(`
agent-secret doctor prints non-secret local diagnostics: expected daemon socket path, audit log path, current platform, and whether the daemon responds.
It never prints secret values or reads 1Password items.
`)
}

type secretFlags struct {
	specs []request.SecretSpec
}

func (s *secretFlags) String() string {
	return fmt.Sprintf("%d secret mapping(s)", len(s.specs))
}

func (s *secretFlags) Set(value string) error {
	alias, ref, ok := strings.Cut(value, "=")
	if !ok || alias == "" || ref == "" {
		return fmt.Errorf("%w: --secret must be ALIAS=op://example", ErrInvalidArguments)
	}
	s.specs = append(s.specs, request.SecretSpec{Alias: alias, Ref: ref})
	return nil
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}
