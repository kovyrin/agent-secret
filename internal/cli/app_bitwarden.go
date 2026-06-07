package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kovyrin/agent-secret/internal/bwsm"
	"golang.org/x/term"
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

type bitwardenInteractiveTokenStore interface {
	PutAllowingUserInteraction(ctx context.Context, token bwsm.Token) error
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
	tokenValue, err := a.readBitwardenTokenValue(command.BitwardenOptions)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	token := bwsm.Token{Alias: command.BitwardenOptions.Alias, AccessToken: tokenValue}
	if err := putBitwardenToken(ctx, store, token, !command.BitwardenOptions.FromStdin); err != nil {
		a.stderrf("agent-secret: install Bitwarden token alias %q: %v\n", command.BitwardenOptions.Alias, err)
		return 1
	}
	return a.writeBitwardenTokenResult(command, true, "installed")
}

func putBitwardenToken(ctx context.Context, store bwsm.Store, token bwsm.Token, allowUserInteraction bool) error {
	if allowUserInteraction {
		if interactiveStore, ok := store.(bitwardenInteractiveTokenStore); ok {
			return interactiveStore.PutAllowingUserInteraction(ctx, token)
		}
	}
	return store.Put(ctx, token)
}

func (a App) readBitwardenTokenValue(opts BitwardenCommandOptions) (string, error) {
	if opts.FromStdin {
		return readBitwardenTokenFromReader(a.stdin(), "stdin")
	}
	prompt := a.SecretPrompt
	if prompt == nil {
		prompt = readSecretFromTerminal
	}
	tokenValue, err := prompt(fmt.Sprintf("Bitwarden Secrets Manager access token for alias %q: ", opts.Alias))
	if err != nil {
		return "", fmt.Errorf("read Bitwarden token interactively: %w", err)
	}
	tokenValue = strings.TrimSpace(tokenValue)
	if tokenValue == "" {
		return "", errors.New("bitwarden token from interactive prompt is empty")
	}
	if len(tokenValue) > 64*1024 {
		return "", errors.New("bitwarden token from interactive prompt exceeds 65536 bytes")
	}
	return tokenValue, nil
}

func readBitwardenTokenFromReader(reader io.Reader, source string) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, 64*1024+1))
	if err != nil {
		return "", fmt.Errorf("read Bitwarden token from %s: %w", source, err)
	}
	if len(raw) > 64*1024 {
		return "", fmt.Errorf("bitwarden token from %s exceeds 65536 bytes", source)
	}
	tokenValue := strings.TrimSpace(string(raw))
	if tokenValue == "" {
		return "", fmt.Errorf("bitwarden token from %s is empty", source)
	}
	return tokenValue, nil
}

func readSecretFromTerminal(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("open controlling terminal: %w", err)
	}
	defer func() { _ = tty.Close() }()

	if prompt != "" {
		if _, err := fmt.Fprint(tty, prompt); err != nil {
			return "", fmt.Errorf("write prompt: %w", err)
		}
	}
	fd := int(tty.Fd()) //nolint:gosec // G115: file descriptors returned by os.File fit term.ReadPassword's int API.
	raw, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(raw), nil
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
