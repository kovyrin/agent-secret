package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/kovyrin/agent-secret/internal/install"
)

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
	force := fs.Bool("force", false, "replace an existing command file or different symlink")
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
	force := fs.Bool("force", false, "replace an existing skill file or different symlink")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: skill-install accepts no positional arguments", ErrInvalidArguments)
	}
	return Command{
		Kind: KindSkillInstall,
		InstallSkillOptions: install.SkillOptions{
			SkillsDir: *skillsDir,
			Force:     *force,
		},
	}, nil
}
