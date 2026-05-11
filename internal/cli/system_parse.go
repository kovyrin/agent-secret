package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/install"
)

type ConfigCommandOptions struct {
	ConfigPath string
}

type ProfileCommandOptions struct {
	ConfigPath string
	Name       string
}

func parseVersion(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: VersionHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: version accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{Kind: KindVersion, OutputJSON: *jsonOutput, VersionText: buildinfo.DisplayVersion()}, nil
}

func parseAgentContext(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: AgentContextHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("agent-context", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "profile config path")
	fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: agent-context accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{
		Kind:                KindAgentContext,
		OutputJSON:          true,
		AgentContextOptions: ConfigCommandOptions{ConfigPath: *configPath},
	}, nil
}

func parseProfile(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: profile requires list or show", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: ProfileHelp()}, ErrHelpRequested
	}
	switch args[0] {
	case "list":
		return parseProfileList(args[1:])
	case "show":
		return parseProfileShow(args[1:])
	default:
		return Command{}, fmt.Errorf(
			"%w: unknown profile subcommand %q; expected one of: list, show",
			ErrInvalidArguments,
			args[0],
		)
	}
}

func parseProfileList(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: ProfileListHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("profile list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "profile config path")
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: profile list accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{
		Kind:           KindProfileList,
		OutputJSON:     *jsonOutput,
		ProfileOptions: ProfileCommandOptions{ConfigPath: *configPath},
	}, nil
}

func parseProfileShow(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: ProfileShowHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("profile show", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "profile config path")
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() > 1 {
		return Command{}, fmt.Errorf("%w: profile show accepts at most one profile name", ErrInvalidArguments)
	}
	name := ""
	if fs.NArg() == 1 {
		name = strings.TrimSpace(fs.Arg(0))
		if name == "" {
			return Command{}, fmt.Errorf("%w: profile show requires a non-empty profile name", ErrInvalidArguments)
		}
	}
	return Command{
		Kind:           KindProfileShow,
		OutputJSON:     *jsonOutput,
		ProfileOptions: ProfileCommandOptions{ConfigPath: *configPath, Name: name},
	}, nil
}

func parseDaemon(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: daemon requires status, start, or stop", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: DaemonHelp()}, ErrHelpRequested
	}
	subcommand := args[0]
	fs := flag.NewFlagSet("daemon "+subcommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: daemon %s accepts no positional arguments", ErrInvalidArguments, subcommand)
	}
	switch subcommand {
	case "status":
		return Command{Kind: KindDaemonStatus, OutputJSON: *jsonOutput}, nil
	case "start":
		return Command{Kind: KindDaemonStart, OutputJSON: *jsonOutput}, nil
	case "stop":
		return Command{Kind: KindDaemonStop, OutputJSON: *jsonOutput}, nil
	default:
		return Command{}, fmt.Errorf(
			"%w: unknown daemon subcommand %q; expected one of: status, start, stop",
			ErrInvalidArguments,
			subcommand,
		)
	}
}

func parseDoctor(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: DoctorHelp()}, ErrHelpRequested
	}
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: doctor accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{Kind: KindDoctor, OutputJSON: *jsonOutput}, nil
}

func parseInstallCLI(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: InstallCLIHelp()}, ErrHelpRequested
	}
	flags, err := parseInstallLinkFlags(args, "install-cli", "bin-dir", "command symlink directory")
	if err != nil {
		return Command{}, err
	}
	return Command{
		Kind:       KindInstallCLI,
		OutputJSON: flags.jsonOutput,
		InstallCLIOptions: install.CLIOptions{
			BinDir: flags.path,
			Force:  flags.force,
		},
	}, nil
}

func parseSkillInstall(args []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: SkillInstallHelp()}, ErrHelpRequested
	}
	flags, err := parseInstallLinkFlags(args, "skill-install", "skills-dir", "agent skills directory")
	if err != nil {
		return Command{}, err
	}
	return Command{
		Kind:       KindSkillInstall,
		OutputJSON: flags.jsonOutput,
		InstallSkillOptions: install.SkillOptions{
			SkillsDir: flags.path,
			Force:     flags.force,
		},
	}, nil
}

type installLinkFlags struct {
	path       string
	force      bool
	jsonOutput bool
}

func parseInstallLinkFlags(args []string, commandName string, pathFlag string, pathUsage string) (installLinkFlags, error) {
	fs := flag.NewFlagSet(commandName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String(pathFlag, "", pathUsage)
	force := fs.Bool("force", false, "replace an existing skill file or different symlink")
	jsonOutput := fs.Bool("json", false, "print JSON output")
	if err := fs.Parse(args); err != nil {
		return installLinkFlags{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return installLinkFlags{}, fmt.Errorf("%w: %s accepts no positional arguments", ErrInvalidArguments, commandName)
	}
	return installLinkFlags{path: *path, force: *force, jsonOutput: *jsonOutput}, nil
}
