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
	"github.com/kovyrin/agent-secret/internal/opaccount"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
	"github.com/kovyrin/agent-secret/internal/request"
)

type execFlags struct {
	reason                 string
	cwd                    string
	ttl                    time.Duration
	profileName            string
	configPath             string
	account                string
	overrideEnv            bool
	forceRefresh           bool
	dryRun                 bool
	reuseOnly              bool
	allowMutableExecutable bool
	secrets                secretFlags
	only                   onlyFlags
	envFiles               envFileFlags
}

type execInputs struct {
	reason  string
	ttl     time.Duration
	env     []string
	secrets []request.SecretSpec
}

type execInputSources struct {
	reason         string
	ttl            time.Duration
	env            []string
	envFileSecrets []request.SecretSpec
	profile        profileconfig.Profile
	loadedProfile  bool
	configAccount  string
}

type filteredExecSecretSources struct {
	profileSecrets []request.SecretSpec
	envFileSecrets []request.SecretSpec
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

	var execOpts execFlags
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&execOpts.reason, "reason", "", "approval reason")
	fs.StringVar(&execOpts.cwd, "cwd", "", "working directory")
	fs.DurationVar(&execOpts.ttl, "ttl", 0, "approval ttl")
	fs.StringVar(&execOpts.profileName, "profile", "", "profile name")
	fs.StringVar(&execOpts.configPath, "config", "", "profile config path")
	fs.StringVar(&execOpts.account, "account", "", "1Password account")
	fs.BoolVar(&execOpts.overrideEnv, "override-env", false, "override existing env aliases")
	fs.BoolVar(&execOpts.forceRefresh, "force-refresh", false, "refresh reusable approval values")
	fs.BoolVar(&execOpts.dryRun, "dry-run", false, "validate request and print preflight output without prompting or spawning")
	fs.BoolVar(&execOpts.reuseOnly, "reuse-only", false, "use an existing reusable approval or fail without prompting")
	fs.BoolVar(
		&execOpts.allowMutableExecutable,
		"allow-mutable-executable",
		false,
		"allow a user-owned or writable executable path after showing an approval warning",
	)
	jsonOutput := fs.Bool("json", false, "unsupported")
	reuse := fs.Bool("reuse", false, "unsupported")
	fs.Var(&execOpts.secrets, "secret", "secret mapping")
	fs.Var(&execOpts.only, "only", "profile alias filter")
	fs.Var(&execOpts.envFiles, "env-file", "dotenv env file")
	if err := fs.Parse(args[:boundary]); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if *jsonOutput && !execOpts.dryRun {
		return Command{}, ErrUnsupportedExecJSON
	}
	if *reuse {
		return Command{}, ErrUnsupportedReuse
	}
	if fs.NArg() != 0 {
		return Command{}, ErrShellStringCommand
	}

	inputs, err := resolveExecInputs(execOpts)
	if err != nil {
		return Command{}, err
	}

	req, err := buildExecRequest(execRequestBuildOptions{
		reason:                 inputs.reason,
		command:                command,
		cwd:                    execOpts.cwd,
		env:                    inputs.env,
		secrets:                inputs.secrets,
		ttl:                    inputs.ttl,
		overrideEnv:            execOpts.overrideEnv,
		forceRefresh:           execOpts.forceRefresh,
		reuseOnly:              execOpts.reuseOnly,
		allowMutableExecutable: execOpts.allowMutableExecutable,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build exec request: %w", err)
	}

	return Command{Kind: KindExec, OutputJSON: *jsonOutput, ExecRequest: req, ExecEnv: inputs.env, ExecDryRun: execOpts.dryRun}, nil
}

func resolveExecInputs(flags execFlags) (execInputs, error) {
	sources, err := loadExecInputSources(flags)
	if err != nil {
		return execInputs{}, err
	}
	secrets, err := resolveExecSecrets(flags, sources)
	if err != nil {
		return execInputs{}, err
	}

	return execInputs{
		reason:  sources.reason,
		ttl:     sources.ttl,
		env:     sources.env,
		secrets: secrets,
	}, nil
}

func loadExecInputSources(flags execFlags) (execInputSources, error) {
	envFileValues, err := loadEnvFiles(flags.envFiles.paths)
	if err != nil {
		return execInputSources{}, err
	}
	childEnv := mergeEnv(os.Environ(), envFileValues.Plain)
	childEnv = removeEnvKeys(childEnv, envFileValues.SecretAliases)
	hasExplicitSource := len(flags.secrets.specs) > 0 || len(flags.envFiles.paths) > 0
	profile, loadedProfile, err := loadExecProfile(flags.profileName, flags.configPath, hasExplicitSource)
	if err != nil {
		return execInputSources{}, err
	}
	configAccount, err := loadExecConfigAccount(flags.profileName, flags.configPath, hasExplicitSource, loadedProfile)
	if err != nil {
		return execInputSources{}, err
	}

	sources := execInputSources{
		reason:         flags.reason,
		ttl:            flags.ttl,
		env:            childEnv,
		envFileSecrets: envFileValues.Secrets,
		profile:        profile,
		loadedProfile:  loadedProfile,
		configAccount:  configAccount,
	}
	if sources.loadedProfile && sources.reason == "" {
		sources.reason = sources.profile.Reason
	}
	if sources.loadedProfile && sources.ttl == 0 {
		sources.ttl = sources.profile.TTL
	}
	return sources, nil
}

func resolveExecSecrets(flags execFlags, sources execInputSources) ([]request.SecretSpec, error) {
	filtered, err := filterExecSecretsByOnly(flags, sources)
	if err != nil {
		return nil, err
	}
	return assembleExecSecrets(flags, sources, filtered), nil
}

func filterExecSecretsByOnly(flags execFlags, sources execInputSources) (filteredExecSecretSources, error) {
	onlyActive := len(flags.only.aliases) > 0
	if onlyActive && !sources.loadedProfile && len(sources.envFileSecrets) == 0 {
		return filteredExecSecretSources{}, fmt.Errorf("%w: --only requires a profile, default_profile, or --env-file secret refs", ErrInvalidArguments)
	}
	remainingOnly := newOnlySet(flags.only.aliases)
	envFileSecrets := filterSecretsByOnly(sources.envFileSecrets, remainingOnly, onlyActive)
	var profileSecrets []request.SecretSpec
	if sources.loadedProfile {
		profileSecrets = filterSecretsByOnly(sources.profile.Secrets, remainingOnly, onlyActive)
	}
	if onlyActive && len(remainingOnly) > 0 {
		return filteredExecSecretSources{}, missingOnlyError(remainingOnly)
	}
	return filteredExecSecretSources{profileSecrets: profileSecrets, envFileSecrets: envFileSecrets}, nil
}

func assembleExecSecrets(
	flags execFlags,
	sources execInputSources,
	filtered filteredExecSecretSources,
) []request.SecretSpec {
	accountFallback := execSecretAccountFallback(flags, sources)
	if sources.loadedProfile {
		return assembleProfileExecSecrets(flags, sources, filtered, accountFallback)
	}
	return assembleDirectExecSecrets(flags, filtered, accountFallback)
}

func execSecretAccountFallback(flags execFlags, sources execInputSources) string {
	accountFallback := execAccountFallback(flags.account)
	if strings.TrimSpace(flags.account) == "" && !sources.loadedProfile && strings.TrimSpace(sources.configAccount) != "" {
		return sources.configAccount
	}
	return accountFallback
}

func assembleProfileExecSecrets(
	flags execFlags,
	sources execInputSources,
	filtered filteredExecSecretSources,
	accountFallback string,
) []request.SecretSpec {
	profileDefaults := applyDefaultAccount(filtered.profileSecrets, accountFallback)
	explicitAccount := profileExplicitSecretAccount(sources, accountFallback)
	explicitSecrets := append(slices.Clone(flags.secrets.specs), filtered.envFileSecrets...)
	explicitSecrets = applyDefaultAccount(explicitSecrets, explicitAccount)
	return append(slices.Clone(profileDefaults), explicitSecrets...)
}

func profileExplicitSecretAccount(sources execInputSources, accountFallback string) string {
	if account := strings.TrimSpace(sources.profile.Account); account != "" {
		return account
	}
	return accountFallback
}

func assembleDirectExecSecrets(
	flags execFlags,
	filtered filteredExecSecretSources,
	accountFallback string,
) []request.SecretSpec {
	cliSecrets := applyDefaultAccount(slices.Clone(flags.secrets.specs), accountFallback)
	envFileSecrets := applyDefaultAccount(filtered.envFileSecrets, accountFallback)
	return append(cliSecrets, envFileSecrets...)
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
	return opaccount.SelectConcreteDesktopAccount("", os.Getenv("OP_ACCOUNT"), opaccount.DetectDefaultDesktopAccount)
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
