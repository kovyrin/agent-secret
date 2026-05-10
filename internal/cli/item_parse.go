package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/profileconfig"
)

type itemDescribeFlags struct {
	account    string
	configPath string
	format     string
	prefix     string
	reason     string
	ttl        time.Duration
}

func (p Parser) parseItem(args []string, fullArgs []string) (Command, error) {
	if len(args) == 0 {
		return Command{}, fmt.Errorf("%w: item requires a subcommand", ErrInvalidArguments)
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: ItemHelp()}, ErrHelpRequested
	}
	if args[0] != "describe" {
		return Command{}, fmt.Errorf("%w: unknown item subcommand %q", ErrInvalidArguments, args[0])
	}
	return p.parseItemDescribe(args[1:], fullArgs)
}

func (p Parser) parseItemDescribe(args []string, fullArgs []string) (Command, error) {
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
		return Command{Kind: KindHelp, HelpText: ItemDescribeHelp()}, ErrHelpRequested
	}

	var flags itemDescribeFlags
	fs := flag.NewFlagSet("item describe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&flags.account, "account", "", "1Password account")
	fs.StringVar(&flags.configPath, "config", "", "profile config path")
	fs.StringVar(&flags.format, "format", string(itemmetadata.FormatText), "output format")
	fs.StringVar(&flags.prefix, "prefix", "", "env alias prefix for env-refs output")
	fs.StringVar(&flags.reason, "reason", "", "approval reason")
	fs.DurationVar(&flags.ttl, "ttl", 0, "approval ttl")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 1 {
		return Command{}, fmt.Errorf("%w: item describe accepts exactly one op:// item reference", ErrInvalidArguments)
	}
	format, err := itemmetadata.ParseFormat(flags.format)
	if err != nil {
		return Command{}, err
	}
	account, err := resolveItemDescribeAccount(flags)
	if err != nil {
		return Command{}, err
	}
	reason := strings.TrimSpace(flags.reason)
	if reason == "" {
		reason = "Inspect 1Password item metadata"
	}
	req, err := buildItemDescribeRequest(itemDescribeRequestBuildOptions{
		reason:  reason,
		command: append([]string{"agent-secret"}, fullArgs...),
		ref:     fs.Arg(0),
		account: account,
		ttl:     flags.ttl,
	})
	if err != nil {
		return Command{}, fmt.Errorf("build item describe request: %w", err)
	}
	return Command{
		Kind:                KindItemDescribe,
		ItemDescribeRequest: req,
		ItemDescribeFormat:  format,
		ItemDescribePrefix:  flags.prefix,
	}, nil
}

func resolveItemDescribeAccount(flags itemDescribeFlags) (string, error) {
	if account := strings.TrimSpace(flags.account); account != "" {
		return account, nil
	}
	metadata, err := profileconfig.LoadMetadata(profileconfig.LoadOptions{
		ConfigPath: flags.configPath,
	})
	if err == nil {
		if account := strings.TrimSpace(metadata.Account); account != "" {
			return account, nil
		}
		return execAccountFallback(flags.account), nil
	}
	if flags.configPath == "" && errors.Is(err, profileconfig.ErrConfigNotFound) {
		return execAccountFallback(flags.account), nil
	}
	return "", fmt.Errorf("load config metadata: %w", err)
}
