package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kovyrin/agent-secret/internal/request"
)

type sessionCreateFlags struct {
	reason      string
	cwd         string
	ttl         time.Duration
	maxReads    int
	profileName string
	configPath  string
	account     string
	overrideEnv bool
	json        bool
	secrets     secretFlags
	only        onlyFlags
	envFiles    envFileFlags
}

type withSessionFlags struct {
	cwd                    string
	allowMutableExecutable bool
	only                   onlyFlags
}

func (p Parser) parseSession(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: session requires create, list, or destroy", ErrInvalidArguments)
	}
	switch args[0] {
	case "-h", "--help", "help":
		return Command{Kind: KindHelp, HelpText: SessionHelp()}, ErrHelpRequested
	case "create":
		return p.parseSessionCreate(args[1:])
	case "list":
		return parseSessionList(args[1:])
	case "destroy":
		return parseSessionDestroy(args[1:])
	default:
		return Command{}, fmt.Errorf("%w: unknown session command %q; expected create, list, or destroy", ErrInvalidArguments, args[0])
	}
}

func (p Parser) parseSessionCreate(args []string) (Command, error) {
	var flags sessionCreateFlags
	fs := flag.NewFlagSet("session create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.reason, "reason", "", "approval reason")
	fs.StringVar(&flags.cwd, "cwd", "", "session working directory")
	fs.DurationVar(&flags.ttl, "ttl", 0, "session ttl")
	fs.IntVar(&flags.maxReads, "max-reads", 0, "session read count")
	fs.StringVar(&flags.profileName, "profile", "", "profile name")
	fs.StringVar(&flags.configPath, "config", "", "profile config path")
	fs.StringVar(&flags.account, "account", "", "1Password account")
	fs.BoolVar(&flags.overrideEnv, "override-env", false, "allow with-session to override existing env aliases")
	fs.BoolVar(&flags.json, "json", false, "print json")
	fs.Var(&flags.secrets, "secret", "secret mapping")
	fs.Var(&flags.only, "only", "profile alias filter")
	fs.Var(&flags.envFiles, "env-file", "dotenv env file")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: session create does not accept a child command", ErrInvalidArguments)
	}

	inputs, err := p.resolveExecInputs(execFlags{
		reason:      flags.reason,
		cwd:         flags.cwd,
		ttl:         flags.ttl,
		profileName: flags.profileName,
		configPath:  flags.configPath,
		account:     flags.account,
		overrideEnv: flags.overrideEnv,
		secrets:     flags.secrets,
		only:        flags.only,
		envFiles:    flags.envFiles,
	})
	if err != nil {
		return Command{}, err
	}
	req, err := buildSessionCreateRequest(sessionCreateRequestBuildOptions{
		reason:      inputs.reason,
		command:     []string{"agent-secret", "session", "create"},
		cwd:         flags.cwd,
		secrets:     inputs.secrets,
		ttl:         inputs.ttl,
		maxReads:    flags.maxReads,
		overrideEnv: flags.overrideEnv,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build session create request: %w", err)
	}
	return Command{Kind: KindSessionCreate, OutputJSON: flags.json, SessionCreateRequest: req}, nil
}

func parseSessionList(args []string) (Command, error) {
	fs := flag.NewFlagSet("session list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "print json")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: session list does not accept arguments", ErrInvalidArguments)
	}
	return Command{Kind: KindSessionList, OutputJSON: *jsonOutput}, nil
}

func parseSessionDestroy(args []string) (Command, error) {
	fs := flag.NewFlagSet("session destroy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "print json")
	all := fs.Bool("all", false, "destroy all active sessions")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if *all {
		if fs.NArg() != 0 {
			return Command{}, fmt.Errorf("%w: session destroy --all does not accept a session id", ErrInvalidArguments)
		}
		return Command{Kind: KindSessionDestroy, OutputJSON: *jsonOutput, SessionDestroyRequest: request.NewSessionDestroyAll()}, nil
	}
	if fs.NArg() != 1 {
		return Command{}, fmt.Errorf("%w: session destroy requires one session id", ErrInvalidArguments)
	}
	req, err := request.NewSessionDestroy(fs.Arg(0))
	if err != nil {
		return Command{}, err
	}
	return Command{Kind: KindSessionDestroy, OutputJSON: *jsonOutput, SessionDestroyRequest: req}, nil
}

func (p Parser) parseWithSession(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: with-session requires a session token and -- command", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: WithSessionHelp()}, ErrHelpRequested
	}
	boundary := indexOf(args, "--")
	if boundary < 0 {
		return Command{}, ErrShellStringCommand
	}
	commandArgs := args[boundary+1:]
	if len(commandArgs) == 0 {
		return Command{}, ErrShellStringCommand
	}
	sessionToken := args[0]
	var flags withSessionFlags
	fs := flag.NewFlagSet("with-session", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.cwd, "cwd", "", "working directory")
	fs.BoolVar(
		&flags.allowMutableExecutable,
		"allow-mutable-executable",
		false,
		"allow a user-owned or writable executable path after showing the approval warning",
	)
	fs.Var(&flags.only, "only", "session alias filter")
	if err := fs.Parse(args[1:boundary]); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: with-session flags must appear after the session id and before --", ErrInvalidArguments)
	}
	env := os.Environ()
	req, err := buildSessionResolveRequest(sessionResolveRequestBuildOptions{
		sessionToken:           sessionToken,
		command:                commandArgs,
		cwd:                    flags.cwd,
		env:                    env,
		allowMutableExecutable: flags.allowMutableExecutable,
		requestedAliases:       flags.only.aliases,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build with-session request: %w", err)
	}
	return Command{Kind: KindWithSession, SessionResolveRequest: req, SessionEnv: env}, nil
}
