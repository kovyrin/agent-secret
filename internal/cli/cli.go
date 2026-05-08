package cli

import (
	"errors"
	"fmt"

	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/opaccount"
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
	KindVersion      Kind = "version"
	KindExec         Kind = "exec"
	KindItemDescribe Kind = "item_describe"
	KindDoctor       Kind = "doctor"
	KindInstallCLI   Kind = "install_cli"
	KindSkillInstall Kind = "skill_install"
	KindDaemonStart  Kind = "daemon_start"
	KindDaemonStop   Kind = "daemon_stop"
	KindDaemonStatus Kind = "daemon_status"
)

type Command struct {
	Kind                Kind
	ExecRequest         request.ExecRequest
	ExecEnv             []string
	ItemDescribeRequest request.ItemDescribeRequest
	ItemDescribeFormat  itemmetadata.Format
	ItemDescribePrefix  string
	InstallCLIOptions   install.CLIOptions
	InstallSkillOptions install.SkillOptions
	HelpText            string
	VersionText         string
}

type Parser struct {
	detectSingleAccount func() string
}

func NewParser() Parser {
	return Parser{detectSingleAccount: opaccount.DetectSingleCLIAccount}
}

func (p Parser) Parse(args []string) (Command, error) {
	if len(args) == 0 {
		return Command{Kind: KindHelp, HelpText: TopHelp()}, ErrHelpRequested
	}

	switch args[0] {
	case "-h", "--help", "help":
		return Command{Kind: KindHelp, HelpText: TopHelp()}, ErrHelpRequested
	case "-v", "--version", "version":
		return Command{Kind: KindVersion, VersionText: buildinfo.DisplayVersion()}, nil
	case "exec":
		return p.parseExec(args[1:])
	case "item":
		return p.parseItem(args[1:], args)
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
