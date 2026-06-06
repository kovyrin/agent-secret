package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/kovyrin/agent-secret/internal/bwsm"
)

type BitwardenTokenOperation string

const (
	BitwardenTokenInstall BitwardenTokenOperation = "install"
	BitwardenTokenStatus  BitwardenTokenOperation = "status"
	BitwardenTokenRemove  BitwardenTokenOperation = "remove"
)

type BitwardenCommandOptions struct {
	Operation BitwardenTokenOperation `json:"operation"`
	Alias     string                  `json:"alias"`
	FromStdin bool                    `json:"from_stdin,omitempty"`
}

func parseBitwarden(args []string) (Command, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return Command{Kind: KindHelp, HelpText: BitwardenHelp()}, ErrHelpRequested
	}
	if len(args) < 3 || args[0] != "secrets-manager" || args[1] != "token" {
		return Command{}, fmt.Errorf("%w: expected bitwarden secrets-manager token install|status|remove", ErrInvalidArguments)
	}
	switch args[2] {
	case "install":
		return parseBitwardenToken(args[3:], BitwardenTokenInstall)
	case "status":
		return parseBitwardenToken(args[3:], BitwardenTokenStatus)
	case "remove":
		return parseBitwardenToken(args[3:], BitwardenTokenRemove)
	case "-h", "--help", "help":
		return Command{Kind: KindHelp, HelpText: BitwardenHelp()}, ErrHelpRequested
	default:
		return Command{}, fmt.Errorf("%w: unknown Bitwarden token command %q", ErrInvalidArguments, args[2])
	}
}

func parseBitwardenToken(args []string, operation BitwardenTokenOperation) (Command, error) {
	opts := BitwardenCommandOptions{Operation: operation}
	fs := flag.NewFlagSet("bitwarden secrets-manager token "+string(operation), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.Alias, "alias", "", "local token alias")
	fs.BoolVar(&opts.FromStdin, "from-stdin", false, "read access token from stdin")
	jsonOutput := fs.Bool("json", false, "print json")
	if err := fs.Parse(args); err != nil {
		return Command{}, fmt.Errorf("%w: %w", ErrInvalidArguments, err)
	}
	if fs.NArg() != 0 {
		return Command{}, fmt.Errorf("%w: unexpected positional arguments: %s", ErrInvalidArguments, strings.Join(fs.Args(), " "))
	}
	opts.Alias = strings.TrimSpace(opts.Alias)
	if opts.Alias == "" {
		return Command{}, fmt.Errorf("%w: --alias is required", ErrInvalidArguments)
	}
	if operation != BitwardenTokenInstall && opts.FromStdin {
		return Command{}, fmt.Errorf("%w: --from-stdin is only valid with token install", ErrInvalidArguments)
	}
	if operation == BitwardenTokenInstall && !opts.FromStdin {
		return Command{}, fmt.Errorf("%w: token install requires --from-stdin", ErrInvalidArguments)
	}
	return Command{Kind: KindBitwarden, OutputJSON: *jsonOutput, BitwardenOptions: opts}, nil
}

func (a App) runBitwarden(ctx context.Context, command Command) int {
	store := a.BitwardenTokens
	if store == nil {
		store = bwsm.NewKeychainStore("")
	}
	switch command.BitwardenOptions.Operation {
	case BitwardenTokenInstall:
		return a.runBitwardenTokenInstall(ctx, store, command)
	case BitwardenTokenStatus:
		return a.runBitwardenTokenStatus(ctx, store, command)
	case BitwardenTokenRemove:
		return a.runBitwardenTokenRemove(ctx, store, command)
	default:
		a.stderrf("agent-secret: unsupported Bitwarden operation %q\n", command.BitwardenOptions.Operation)
		return 2
	}
}

func (a App) runBitwardenTokenInstall(ctx context.Context, store bwsm.Store, command Command) int {
	raw, err := io.ReadAll(io.LimitReader(a.stdin(), 64*1024+1))
	if err != nil {
		a.stderrf("agent-secret: read Bitwarden token from stdin: %v\n", err)
		return 1
	}
	if len(raw) > 64*1024 {
		a.stderrf("agent-secret: Bitwarden token from stdin exceeds 65536 bytes\n")
		return 1
	}
	tokenValue := strings.TrimSpace(string(raw))
	if tokenValue == "" {
		a.stderrf("agent-secret: Bitwarden token from stdin is empty\n")
		return 1
	}
	token := bwsm.Token{Alias: command.BitwardenOptions.Alias, AccessToken: tokenValue}
	if err := store.Put(ctx, token); err != nil {
		a.stderrf("agent-secret: install Bitwarden token alias %q: %v\n", command.BitwardenOptions.Alias, err)
		return 1
	}
	return a.writeBitwardenTokenResult(command, true, "installed")
}

func (a App) runBitwardenTokenStatus(ctx context.Context, store bwsm.Store, command Command) int {
	_, found, err := store.Get(ctx, command.BitwardenOptions.Alias)
	if err != nil {
		a.stderrf("agent-secret: inspect Bitwarden token alias %q: %v\n", command.BitwardenOptions.Alias, err)
		return 1
	}
	if !found {
		if command.OutputJSON {
			if writeErr := a.writeJSON(bitwardenTokenResult(command, false, "missing")); writeErr != nil {
				a.stderrf("agent-secret: write json: %v\n", writeErr)
			}
		} else {
			a.stdoutf("Bitwarden Secrets Manager token alias %q: missing\n", command.BitwardenOptions.Alias)
		}
		return 1
	}
	return a.writeBitwardenTokenResult(command, true, "installed")
}

func (a App) runBitwardenTokenRemove(ctx context.Context, store bwsm.Store, command Command) int {
	deleted, err := store.Delete(ctx, command.BitwardenOptions.Alias)
	if err != nil {
		a.stderrf("agent-secret: remove Bitwarden token alias %q: %v\n", command.BitwardenOptions.Alias, err)
		return 1
	}
	status := "removed"
	if !deleted {
		status = "missing"
	}
	return a.writeBitwardenTokenResult(command, deleted, status)
}

func (a App) writeBitwardenTokenResult(command Command, ok bool, status string) int {
	if command.OutputJSON {
		if err := a.writeJSON(bitwardenTokenResult(command, ok, status)); err != nil {
			a.stderrf("agent-secret: write json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutf("Bitwarden Secrets Manager token alias %q: %s\n", command.BitwardenOptions.Alias, status)
	return 0
}

func bitwardenTokenResult(command Command, ok bool, status string) map[string]any {
	return map[string]any{
		"schema_version": "1",
		"ok":             ok,
		"alias":          command.BitwardenOptions.Alias,
		"status":         status,
	}
}

func (a App) stdin() io.Reader {
	if a.Stdin != nil {
		return a.Stdin
	}
	return strings.NewReader("")
}
