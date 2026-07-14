package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
	"github.com/kovyrin/agent-secret/internal/request"
)

type gcpExecFlags struct {
	reason                 string
	cwd                    string
	ttl                    time.Duration
	profileName            string
	configPath             string
	googleAccount          string
	project                string
	serviceAccount         string
	dryRun                 bool
	reuseOnly              bool
	allowMutableExecutable bool
	scopes                 repeatedStringFlags
}

type gcpSessionCreateFlags struct {
	reason           string
	ttl              time.Duration
	profileName      string
	configPath       string
	maxCommandStarts int
}

type gcpSessionListFlags struct {
	json bool
}

type gcpWithSessionFlags struct {
	cwd                    string
	allowMutableExecutable bool
}

type gcpAuthStatusFlags struct {
	googleAccount string
	json          bool
}

type gcpAuthLoginFlags struct {
	googleAccount string
	expectedEmail string
	json          bool
}

type gcpExecInputs struct {
	reason      string
	ttl         time.Duration
	access      request.GCPAccess
	profileName string
	configRoot  string
}

func (p Parser) parseGCP(args []string) (Command, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: GCPHelp()}, ErrHelpRequested
	}
	switch args[0] {
	case "exec":
		return p.parseGCPExec(args[1:])
	case "with-session":
		return p.parseGCPWithSession(args[1:])
	case "session":
		return p.parseGCPSession(args[1:])
	case "auth":
		return p.parseGCPAuth(args[1:])
	default:
		return Command{}, fmt.Errorf("%w: unknown gcp command %q; expected one of: auth, exec, session, with-session", ErrInvalidArguments, args[0])
	}
}

func (p Parser) parseGCPExec(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: gcp exec requires flags and -- command", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: GCPExecHelp()}, ErrHelpRequested
	}
	boundary := indexOfDoubleDash(args)
	if boundary < 0 {
		return Command{}, ErrShellStringCommand
	}
	command := args[boundary+1:]
	if len(command) == 0 {
		return Command{}, ErrShellStringCommand
	}

	var flags gcpExecFlags
	flags.scopes.name = "scope"
	fs := flag.NewFlagSet("gcp exec", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.reason, "reason", "", "approval reason")
	fs.StringVar(&flags.cwd, "cwd", "", "working directory")
	fs.DurationVar(&flags.ttl, "ttl", 0, "approval ttl")
	fs.StringVar(&flags.profileName, "profile", "", "profile name")
	fs.StringVar(&flags.configPath, "config", "", "profile config path")
	fs.StringVar(&flags.googleAccount, "google-account", "", "Google bootstrap account alias")
	fs.StringVar(&flags.project, "project", "", "intended GCP project")
	fs.StringVar(&flags.serviceAccount, "service-account", "", "impersonated service account")
	fs.Var(&flags.scopes, "scope", "OAuth scope")
	fs.BoolVar(&flags.dryRun, "dry-run", false, "validate request without prompting or spawning")
	fs.BoolVar(&flags.reuseOnly, "reuse-only", false, "use an existing reusable approval or fail without prompting")
	fs.BoolVar(
		&flags.allowMutableExecutable,
		"allow-mutable-executable",
		false,
		"allow a user-owned or writable executable path after showing an approval warning",
	)
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args[:boundary]); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if *jsonOutput && !flags.dryRun {
		return Command{}, ErrUnsupportedExecJSON
	}
	if fs.NArg() != 0 {
		return Command{}, ErrShellStringCommand
	}

	inputs, err := resolveGCPExecInputs(flags)
	if err != nil {
		return Command{}, err
	}
	env := childEnvWithoutAmbientGCP(os.Environ())
	req, err := buildGCPExecRequest(gcpRequestBuildOptions{
		reason:                 inputs.reason,
		command:                command,
		cwd:                    flags.cwd,
		env:                    env,
		access:                 inputs.access,
		profileName:            inputs.profileName,
		configRoot:             inputs.configRoot,
		ttl:                    inputs.ttl,
		reuseOnly:              flags.reuseOnly,
		allowMutableExecutable: flags.allowMutableExecutable,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build gcp exec request: %w", err)
	}
	return Command{Kind: KindGCPExec, OutputJSON: *jsonOutput, GCPExecRequest: req, GCPEnv: env, GCPDryRun: flags.dryRun}, nil
}

func resolveGCPExecInputs(flags gcpExecFlags) (gcpExecInputs, error) {
	profile, loaded, err := loadGCPProfile(flags.profileName, flags.configPath, flags.hasExplicitAccess())
	if err != nil {
		return gcpExecInputs{}, err
	}
	inputs := gcpExecInputs{
		reason:      flags.reason,
		ttl:         flags.ttl,
		access:      request.GCPAccess{GoogleAccount: flags.googleAccount, Project: flags.project, ServiceAccount: flags.serviceAccount, Scopes: flags.scopes.values},
		profileName: flags.profileName,
	}
	if loaded {
		if profile.GCP == nil {
			return gcpExecInputs{}, fmt.Errorf("%w: profile %q does not define a gcp block", profileconfig.ErrInvalidConfig, profile.Name)
		}
		inputs.profileName = profile.Name
		inputs.configRoot = filepath.Dir(profile.SourcePath)
		if inputs.reason == "" {
			inputs.reason = profile.Reason
		}
		if inputs.ttl == 0 {
			inputs.ttl = profile.TTL
		}
		inputs.access = mergeGCPAccess(*profile.GCP, inputs.access)
	}
	if !loaded && !flags.hasExplicitAccess() {
		return gcpExecInputs{}, fmt.Errorf("%w: gcp exec requires --profile or explicit --google-account, --project, --service-account, and --scope", ErrInvalidArguments)
	}
	return inputs, nil
}

func (f gcpExecFlags) hasExplicitAccess() bool {
	return f.googleAccount != "" || f.project != "" || f.serviceAccount != "" || len(f.scopes.values) > 0
}

func loadGCPProfile(profileName string, configPath string, hasExplicitAccess bool) (profileconfig.Profile, bool, error) {
	if profileName == "" && hasExplicitAccess {
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
	return profileconfig.Profile{}, false, fmt.Errorf("load gcp profile %q: %w", label, err)
}

func mergeGCPAccess(base request.GCPAccess, override request.GCPAccess) request.GCPAccess {
	if override.GoogleAccount != "" {
		base.GoogleAccount = override.GoogleAccount
	}
	if override.Project != "" {
		base.Project = override.Project
	}
	if override.ServiceAccount != "" {
		base.ServiceAccount = override.ServiceAccount
	}
	if len(override.Scopes) > 0 {
		base.Scopes = override.Scopes
	}
	return base
}

func (p Parser) parseGCPSession(args []string) (Command, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: GCPSessionHelp()}, ErrHelpRequested
	}
	switch args[0] {
	case "create":
		return p.parseGCPSessionCreate(args[1:])
	case "list":
		return p.parseGCPSessionList(args[1:])
	case "destroy":
		return p.parseGCPSessionDestroy(args[1:])
	default:
		return Command{}, fmt.Errorf("%w: unknown gcp session command %q; expected one of: create, destroy, list", ErrInvalidArguments, args[0])
	}
}

func (p Parser) parseGCPSessionCreate(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: GCPSessionCreateHelp()}, ErrHelpRequested
	}
	var flags gcpSessionCreateFlags
	fs := flag.NewFlagSet("gcp session create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.reason, "reason", "", "approval reason")
	fs.DurationVar(&flags.ttl, "ttl", 0, "session ttl")
	fs.StringVar(&flags.profileName, "profile", "", "profile name")
	fs.StringVar(&flags.configPath, "config", "", "profile config path")
	fs.IntVar(&flags.maxCommandStarts, "max-command-starts", 0, "maximum with-session command starts")
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: unexpected arguments: %v", ErrInvalidArguments, fs.Args())
	}
	profile, err := profileconfig.Load(profileconfig.LoadOptions{Name: flags.profileName, ConfigPath: flags.configPath})
	if err != nil {
		label := flags.profileName
		if label == "" {
			label = "default"
		}
		return Command{}, fmt.Errorf("load gcp session profile %q: %w", label, err)
	}
	if profile.GCP == nil {
		return Command{}, fmt.Errorf("%w: profile %q does not define a gcp block", profileconfig.ErrInvalidConfig, profile.Name)
	}
	reason := flags.reason
	if reason == "" {
		reason = profile.Reason
	}
	ttl := flags.ttl
	if ttl == 0 {
		ttl = profile.TTL
	}
	configSourcePath, err := pathresolve.Strict(profile.SourcePath)
	if err != nil {
		return Command{}, fmt.Errorf("resolve gcp session profile path: %w", err)
	}
	req, err := request.NewGCPSessionCreate(request.GCPSessionCreateOptions{
		Reason:           reason,
		Access:           *profile.GCP,
		ProfileName:      profile.Name,
		ConfigSourcePath: configSourcePath,
		ProjectRoot:      filepath.Dir(configSourcePath),
		TTL:              ttl,
		MaxCommandStarts: flags.maxCommandStarts,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build gcp session create request: %w", err)
	}
	return Command{Kind: KindGCPSessionCreate, OutputJSON: *jsonOutput, GCPSessionCreateRequest: req}, nil
}

func (p Parser) parseGCPSessionList(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: GCPSessionListHelp()}, ErrHelpRequested
	}
	var flags gcpSessionListFlags
	fs := flag.NewFlagSet("gcp session list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&flags.json, "json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: unexpected arguments: %v", ErrInvalidArguments, fs.Args())
	}
	return Command{Kind: KindGCPSessionList, OutputJSON: flags.json}, nil
}

func (p Parser) parseGCPSessionDestroy(args []string) (Command, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: GCPSessionDestroyHelp()}, ErrHelpRequested
	}
	var jsonOutput bool
	fs := flag.NewFlagSet("gcp session destroy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&jsonOutput, "json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 1 {
		return Command{}, fmt.Errorf("%w: gcp session destroy requires exactly one session handle", ErrInvalidArguments)
	}
	cwd, err := normalizeCWD("")
	if err != nil {
		return Command{}, err
	}
	req, err := request.NewGCPSessionDestroy(fs.Arg(0), cwd)
	if err != nil {
		return Command{}, err
	}
	return Command{Kind: KindGCPSessionDestroy, OutputJSON: jsonOutput, GCPSessionDestroyRequest: req}, nil
}

func (p Parser) parseGCPWithSession(args []string) (Command, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: GCPWithSessionHelp()}, ErrHelpRequested
	}
	boundary := indexOfDoubleDash(args)
	if boundary < 0 {
		return Command{}, ErrShellStringCommand
	}
	if boundary < 1 {
		return Command{}, fmt.Errorf("%w: gcp with-session requires HANDLE -- COMMAND [ARG...]", ErrInvalidArguments)
	}
	command := args[boundary+1:]
	if len(command) == 0 {
		return Command{}, ErrShellStringCommand
	}
	var flags gcpWithSessionFlags
	fs := flag.NewFlagSet("gcp with-session", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.cwd, "cwd", "", "working directory")
	fs.BoolVar(
		&flags.allowMutableExecutable,
		"allow-mutable-executable",
		false,
		"allow a user-owned or writable executable path",
	)
	if err := fs.Parse(args[1:boundary]); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: gcp with-session flags must appear after the session handle and before --", ErrInvalidArguments)
	}
	env := childEnvWithoutAmbientGCP(os.Environ())
	req, err := buildGCPSessionUseRequest(gcpSessionUseRequestBuildOptions{
		sessionHandle:          args[0],
		command:                command,
		cwd:                    flags.cwd,
		env:                    env,
		allowMutableExecutable: flags.allowMutableExecutable,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build gcp with-session request: %w", err)
	}
	return Command{Kind: KindGCPWithSession, GCPSessionUseRequest: req, GCPEnv: env}, nil
}

func (p Parser) parseGCPAuth(args []string) (Command, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: GCPAuthHelp()}, ErrHelpRequested
	}
	switch args[0] {
	case "status":
		return p.parseGCPAuthStatus(args[1:])
	case "login":
		return p.parseGCPAuthLogin(args[1:])
	case "logout":
		return p.parseGCPAuthLogout(args[1:])
	default:
		return Command{}, fmt.Errorf("%w: unknown gcp auth command %q; expected one of: login, logout, status", ErrInvalidArguments, args[0])
	}
}

func (p Parser) parseGCPAuthStatus(args []string) (Command, error) {
	return parseGCPAuthAccountJSONCommand(args, "gcp auth status", GCPAuthStatusHelp, func(account string, jsonOutput bool) (Command, error) {
		req, err := request.NewGCPAuthStatus(account)
		if err != nil {
			return Command{}, err
		}
		return Command{Kind: KindGCPAuthStatus, OutputJSON: jsonOutput, GCPAuthStatusRequest: req}, nil
	})
}

func (p Parser) parseGCPAuthLogin(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: GCPAuthLoginHelp()}, ErrHelpRequested
	}
	var flags gcpAuthLoginFlags
	fs := flag.NewFlagSet("gcp auth login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.googleAccount, "google-account", "", "Google bootstrap account alias")
	fs.StringVar(&flags.expectedEmail, "expected-email", "", "expected Google email")
	fs.BoolVar(&flags.json, "json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: unexpected arguments: %v", ErrInvalidArguments, fs.Args())
	}
	req, err := request.NewGCPAuthLogin(request.GCPAuthLoginOptions{
		GoogleAccount: flags.googleAccount,
		ExpectedEmail: flags.expectedEmail,
	})
	if err != nil {
		return Command{}, err
	}
	return Command{Kind: KindGCPAuthLogin, OutputJSON: flags.json, GCPAuthLoginRequest: req}, nil
}

func (p Parser) parseGCPAuthLogout(args []string) (Command, error) {
	return parseGCPAuthAccountJSONCommand(args, "gcp auth logout", GCPAuthLogoutHelp, func(account string, jsonOutput bool) (Command, error) {
		req, err := request.NewGCPAuthLogout(account)
		if err != nil {
			return Command{}, err
		}
		return Command{Kind: KindGCPAuthLogout, OutputJSON: jsonOutput, GCPAuthLogoutRequest: req}, nil
	})
}

func parseGCPAuthAccountJSONCommand(
	args []string,
	name string,
	help func() string,
	build func(account string, jsonOutput bool) (Command, error),
) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: help()}, ErrHelpRequested
	}
	var flags gcpAuthStatusFlags
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.googleAccount, "google-account", "", "Google bootstrap account alias")
	fs.BoolVar(&flags.json, "json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: unexpected arguments: %v", ErrInvalidArguments, fs.Args())
	}
	return build(flags.googleAccount, flags.json)
}
