package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/envfile"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/opresolver"
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
	KindInstallCLI   Kind = "install_cli"
	KindSkillInstall Kind = "skill_install"
	KindDaemonStart  Kind = "daemon_start"
	KindDaemonStop   Kind = "daemon_stop"
	KindDaemonStatus Kind = "daemon_status"
)

type Command struct {
	Kind              Kind
	ExecRequest       request.ExecRequest
	InstallCLIOptions install.CLIOptions
	InstallSkillOpts  install.SkillOptions
	HelpText          string
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
	case "install-cli":
		return parseInstallCLI(args[1:])
	case "skill-install":
		return parseSkillInstall(args[1:])
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
  install-cli Install or repair the agent-secret command symlink for this user.
  skill-install Install or repair the Agent Secret agent skill for this user.
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

  agent-secret exec --reason "Run legacy dotenv command" \
    --env-file .env \
    -- npm run deploy

  agent-secret exec --reason "Use a deliberate shell wrapper" \
    --secret TOKEN=op://Example/Item/token \
    -- sh -c 'echo "$TOKEN" >/dev/null'

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
  - By default, the daemon uses the personal 1Password sign-in address my.1password.com. Set AGENT_SECRET_1PASSWORD_ACCOUNT only to override it.
  - The wrapped command must appear after -- as argv. agent-secret does not parse shell strings.
  - Commands from current-user-writable files or directories are rejected unless --allow-mutable-executable is set.
  - exec has no --json mode and never prints secret values.
  - Text file/document refs such as op://Example/GitHub App/key.pem are injected as env values; binary attachments are not supported.
  - agent-secret skill-install links the bundled Agent Secret skill into ~/.agents/skills/agent-secret.
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
  --allow-mutable-executable
                      Permit a project or temp executable that can be replaced by the current user.
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
  Explicit --secret-only invocations do not load default_profile.
  CLI --reason and --ttl override profile defaults.
  Account precedence is per-secret account, profile account, top-level account,
  --account, OP_ACCOUNT / AGENT_SECRET_1PASSWORD_ACCOUNT, then my.1password.com.
  Included profiles are resolved in order. Later includes and the selected
  profile override earlier secrets with the same alias.
  1Password text file/document refs are resolved into the alias env value with
  multiline text preserved. Binary attachments are not supported by env-var
  delivery.

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
	var only onlyFlags
	var envFiles envFileFlags
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reason := fs.String("reason", "", "approval reason")
	cwd := fs.String("cwd", "", "working directory")
	ttl := fs.Duration("ttl", 0, "approval ttl")
	profileName := fs.String("profile", "", "profile name")
	configPath := fs.String("config", "", "profile config path")
	account := fs.String("account", "", "1Password account")
	overrideEnv := fs.Bool("override-env", false, "override existing env aliases")
	forceRefresh := fs.Bool("force-refresh", false, "refresh reusable approval values")
	allowMutableExecutable := fs.Bool("allow-mutable-executable", false, "allow mutable executable path")
	jsonOutput := fs.Bool("json", false, "unsupported")
	reuse := fs.Bool("reuse", false, "unsupported")
	fs.Var(&secrets, "secret", "secret mapping")
	fs.Var(&only, "only", "profile alias filter")
	fs.Var(&envFiles, "env-file", "dotenv env file")
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
	envFileValues, err := loadEnvFiles(envFiles.paths)
	if err != nil {
		return Command{}, err
	}
	childEnv := mergeEnv(os.Environ(), envFileValues.Plain)
	childEnv = removeEnvKeys(childEnv, envFileValues.SecretAliases)
	hasExplicitSource := len(secrets.specs) > 0 || len(envFiles.paths) > 0
	profile, loadedProfile, err := loadExecProfile(*profileName, *configPath, hasExplicitSource)
	if err != nil {
		return Command{}, err
	}
	configAccount, err := loadExecConfigAccount(*profileName, *configPath, hasExplicitSource, loadedProfile)
	if err != nil {
		return Command{}, err
	}
	onlyActive := len(only.aliases) > 0
	if onlyActive && !loadedProfile && len(envFileValues.Secrets) == 0 {
		return Command{}, fmt.Errorf("%w: --only requires a profile, default_profile, or --env-file secret refs", ErrInvalidArguments)
	}
	if loadedProfile && effectiveReason == "" {
		effectiveReason = profile.Reason
	}
	if loadedProfile && effectiveTTL == 0 {
		effectiveTTL = profile.TTL
	}
	remainingOnly := newOnlySet(only.aliases)
	envFileSecrets := filterSecretsByOnly(envFileValues.Secrets, remainingOnly, onlyActive)
	var profileSecrets []request.SecretSpec
	if loadedProfile {
		profileSecrets = filterSecretsByOnly(profile.Secrets, remainingOnly, onlyActive)
	}
	if onlyActive && len(remainingOnly) > 0 {
		return Command{}, missingOnlyError(remainingOnly)
	}

	accountFallback := execAccountFallback(*account)
	if !loadedProfile && strings.TrimSpace(configAccount) != "" {
		accountFallback = configAccount
	}
	var effectiveSecrets []request.SecretSpec
	if loadedProfile {
		profileSecrets = applyDefaultAccount(profileSecrets, accountFallback)
		cliAccount := profile.Account
		if strings.TrimSpace(cliAccount) == "" {
			cliAccount = accountFallback
		}
		effectiveSecrets = append(slices.Clone(profileSecrets), applyDefaultAccount(append(slices.Clone(secrets.specs), envFileSecrets...), cliAccount)...)
	} else {
		effectiveSecrets = append(applyDefaultAccount(slices.Clone(secrets.specs), accountFallback), applyDefaultAccount(envFileSecrets, accountFallback)...)
	}

	req, err := request.NewExec(request.ExecOptions{
		Reason:                 effectiveReason,
		Command:                command,
		CWD:                    *cwd,
		Env:                    childEnv,
		Secrets:                effectiveSecrets,
		TTL:                    effectiveTTL,
		ReceivedAt:             p.now(),
		DeliveryMode:           request.DeliveryEnvExec,
		OverrideEnv:            *overrideEnv,
		ForceRefresh:           *forceRefresh,
		AllowMutableExecutable: *allowMutableExecutable,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build exec request: %w", err)
	}

	return Command{Kind: KindExec, ExecRequest: req}, nil
}

func loadExecProfile(profileName string, configPath string, hasExplicitSource bool) (profileconfig.Profile, bool, error) {
	if profileName == "" && hasExplicitSource {
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

func loadExecConfigAccount(profileName string, configPath string, hasExplicitSource bool, loadedProfile bool) (string, error) {
	if profileName != "" || !hasExplicitSource || loadedProfile {
		return "", nil
	}
	metadata, err := profileconfig.LoadMetadata(profileconfig.LoadOptions{
		ConfigPath: configPath,
	})
	if err == nil {
		return metadata.Account, nil
	}
	if configPath == "" && errors.Is(err, profileconfig.ErrConfigNotFound) {
		return "", nil
	}
	return "", fmt.Errorf("load config metadata: %w", err)
}

func applyDefaultAccount(secrets []request.SecretSpec, account string) []request.SecretSpec {
	account = strings.TrimSpace(account)
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

func execAccountFallback(cliAccount string) string {
	if account := strings.TrimSpace(cliAccount); account != "" {
		return account
	}
	if account := strings.TrimSpace(os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT")); account != "" {
		return account
	}
	if account := strings.TrimSpace(os.Getenv("OP_ACCOUNT")); account != "" {
		return account
	}
	return opresolver.DefaultDesktopAccount
}

func newOnlySet(aliases []string) map[string]struct{} {
	if len(aliases) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(aliases))
	for _, alias := range aliases {
		allowed[alias] = struct{}{}
	}
	return allowed
}

func filterSecretsByOnly(secrets []request.SecretSpec, remaining map[string]struct{}, active bool) []request.SecretSpec {
	if !active {
		return slices.Clone(secrets)
	}
	filtered := make([]request.SecretSpec, 0, len(secrets))
	for _, secret := range secrets {
		if _, ok := remaining[secret.Alias]; ok {
			filtered = append(filtered, secret)
			delete(remaining, secret.Alias)
		}
	}
	return filtered
}

func missingOnlyError(remaining map[string]struct{}) error {
	missing := make([]string, 0, len(remaining))
	for alias := range remaining {
		missing = append(missing, alias)
	}
	slices.Sort(missing)
	return fmt.Errorf("%w: --only alias not found in profile or env file: %s", ErrInvalidArguments, strings.Join(missing, ", "))
}

type envFileValues struct {
	Plain         map[string]string
	Secrets       []request.SecretSpec
	SecretAliases []string
}

func loadEnvFiles(paths []string) (envFileValues, error) {
	values := envFileValues{
		Plain: make(map[string]string),
	}
	secretByAlias := make(map[string]request.SecretSpec)
	for _, path := range paths {
		entries, err := envfile.Load(path)
		if err != nil {
			return envFileValues{}, err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Value, "op://") {
				delete(values.Plain, entry.Key)
				secretByAlias[entry.Key] = request.SecretSpec{Alias: entry.Key, Ref: entry.Value}
				continue
			}
			delete(secretByAlias, entry.Key)
			values.Plain[entry.Key] = entry.Value
		}
	}
	aliases := make([]string, 0, len(secretByAlias))
	for alias := range secretByAlias {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	for _, alias := range aliases {
		secret := secretByAlias[alias]
		values.Secrets = append(values.Secrets, secret)
		values.SecretAliases = append(values.SecretAliases, alias)
	}
	return values, nil
}

func mergeEnv(base []string, overlay map[string]string) []string {
	if len(overlay) == 0 {
		return slices.Clone(base)
	}
	positions := make(map[string]int, len(base))
	out := slices.Clone(base)
	for index, entry := range out {
		key, _, ok := strings.Cut(entry, "=")
		if ok {
			positions[key] = index
		}
	}
	keys := make([]string, 0, len(overlay))
	for key := range overlay {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		entry := key + "=" + overlay[key]
		if index, ok := positions[key]; ok {
			out[index] = entry
			continue
		}
		out = append(out, entry)
	}
	return out
}

func removeEnvKeys(env []string, keys []string) []string {
	if len(keys) == 0 {
		return env
	}
	remove := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		remove[key] = struct{}{}
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			out = append(out, entry)
			continue
		}
		if _, found := remove[key]; found {
			continue
		}
		out = append(out, entry)
	}
	return out
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

func parseInstallCLI(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: InstallCLIHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("install-cli", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binDir := fs.String("bin-dir", "", "command symlink directory")
	force := fs.Bool("force", false, "replace an existing non-symlink command path")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: install-cli accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{
		Kind: KindInstallCLI,
		InstallCLIOptions: install.CLIOptions{
			BinDir: *binDir,
			Force:  *force,
		},
	}, nil
}

func parseSkillInstall(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: SkillInstallHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("skill-install", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	skillsDir := fs.String("skills-dir", "", "agent skills directory")
	force := fs.Bool("force", false, "replace an existing non-symlink skill path")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: skill-install accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{
		Kind: KindSkillInstall,
		InstallSkillOpts: install.SkillOptions{
			SkillsDir: *skillsDir,
			Force:     *force,
		},
	}, nil
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

When run from a development or test build, it links to the executable that is
currently running. If the command is already a symlink to that executable, it is
left in place. Existing regular files are not replaced unless --force is passed.

Flags:

  --bin-dir DIR  Directory that should contain the agent-secret command. Defaults to ~/.local/bin.
  --force        Replace an existing non-symlink file at DIR/agent-secret.
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

Flags:

  --skills-dir DIR  Directory that should contain the agent-secret skill. Defaults to ~/.agents/skills.
  --force           Replace an existing non-symlink path at DIR/agent-secret.
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

type onlyFlags struct {
	aliases []string
}

func (o *onlyFlags) String() string {
	return strings.Join(o.aliases, ",")
}

type envFileFlags struct {
	paths []string
}

func (e *envFileFlags) String() string {
	return strings.Join(e.paths, ",")
}

func (e *envFileFlags) Set(value string) error {
	path := strings.TrimSpace(value)
	if path == "" {
		return fmt.Errorf("%w: --env-file requires a path", ErrInvalidArguments)
	}
	e.paths = append(e.paths, path)
	return nil
}

func (o *onlyFlags) Set(value string) error {
	for rawAlias := range strings.SplitSeq(value, ",") {
		alias := strings.TrimSpace(rawAlias)
		if alias == "" {
			return fmt.Errorf("%w: --only must name non-empty aliases", ErrInvalidArguments)
		}
		o.aliases = append(o.aliases, alias)
	}
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
