package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/opresolver"
	"github.com/kovyrin/agent-secret/internal/processhardening"
)

func main() {
	os.Exit(run())
}

func run() int {
	if err := processhardening.DisableCoreDumps(); err != nil {
		stderrf("agent-secretd: harden process: %v\n", err)
		return 1
	}

	config, err := parseDaemonConfig(os.Args[1:])
	if err != nil {
		stderrf("agent-secretd: parse flags: %v\n", err)
		return 2
	}

	auditWriter, err := audit.OpenDefault(nil)
	if err != nil {
		stderrf("agent-secretd: open audit log: %v\n", err)
		return 1
	}
	defer func() { _ = auditWriter.Close() }()

	approver, err := daemon.NewSocketApprover(
		config.socketPath,
		daemon.ProcessApproverLauncher{},
		nil,
	)
	if err != nil {
		stderrf("agent-secretd: initialize approver: %v\n", err)
		return 1
	}

	broker, err := daemon.NewBroker(daemon.BrokerOptions{
		Approver: approver,
		Resolver: newResolver(config.accountName),
		Audit:    auditWriter,
	})
	if err != nil {
		stderrf("agent-secretd: initialize broker: %v\n", err)
		return 1
	}
	server, err := daemon.NewServer(daemon.ServerOptions{
		Broker:        broker,
		Approvals:     approver,
		ExecValidator: daemon.NewTrustedExecutableValidator(daemon.DefaultTrustedClientPaths()),
	})
	if err != nil {
		stderrf("agent-secretd: initialize server: %v\n", err)
		return 1
	}
	if err := server.ListenAndServe(context.Background(), config.socketPath); err != nil {
		stderrf("agent-secretd: %v\n", err)
		return 1
	}
	return 0
}

type daemonConfig struct {
	socketPath  string
	accountName string
}

func parseDaemonConfig(args []string) (daemonConfig, error) {
	socketPath, err := daemon.DefaultSocketPath()
	if err != nil {
		return daemonConfig{}, fmt.Errorf("resolve default socket path: %w", err)
	}

	config := daemonConfig{}
	flags := flag.NewFlagSet("agent-secretd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.socketPath, "socket", socketPath, "daemon socket path")
	flags.StringVar(
		&config.accountName,
		"account",
		os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT"),
		"1Password account sign-in address, name, or UUID; empty uses OP_ACCOUNT or my.1password.com",
	)
	if err := flags.Parse(args); err != nil {
		return daemonConfig{}, err
	}
	if flags.NArg() != 0 {
		return daemonConfig{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return config, nil
}

func stderrf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
}

type desktopResolver struct {
	mu                 sync.Mutex
	account            string
	clients            map[string]*opresolver.Resolver
	inits              map[string]*desktopResolverInit
	newDesktopResolver desktopResolverFactory
}

type desktopResolverResult struct {
	resolver *opresolver.Resolver
	err      error
}

type desktopResolverFactory func(context.Context, opresolver.ClientOptions) (*opresolver.Resolver, error)

type desktopResolverInit struct {
	done     chan struct{}
	resolver *opresolver.Resolver
	err      error
}

func newResolver(account string) daemon.Resolver {
	account = strings.TrimSpace(account)
	return &desktopResolver{
		account:            account,
		clients:            make(map[string]*opresolver.Resolver),
		inits:              make(map[string]*desktopResolverInit),
		newDesktopResolver: opresolver.NewDesktopResolver,
	}
}

func (r *desktopResolver) Resolve(ctx context.Context, ref string, account string) (string, error) {
	resolver, err := r.client(ctx, account)
	if err != nil {
		return "", fmt.Errorf("create 1Password resolver: %w", err)
	}
	secret, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve secret: %w", err)
	}
	return secret.Value(), nil
}

func (r *desktopResolver) client(ctx context.Context, accountOverride string) (*opresolver.Resolver, error) {
	account := r.effectiveAccount(accountOverride)
	resolver, init, owner := r.startClientInit(account)
	if resolver != nil {
		return resolver, nil
	}
	if !owner {
		return waitForClientInit(ctx, init)
	}

	resolver, err := r.createClient(ctx, account)
	r.finishClientInit(account, init, resolver, err)
	return resolver, err
}

func (r *desktopResolver) startClientInit(account string) (*opresolver.Resolver, *desktopResolverInit, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if resolver := r.clients[account]; resolver != nil {
		return resolver, nil, false
	}
	if init := r.inits[account]; init != nil {
		return nil, init, false
	}
	if r.inits == nil {
		r.inits = make(map[string]*desktopResolverInit)
	}
	init := &desktopResolverInit{done: make(chan struct{})}
	r.inits[account] = init
	return nil, init, true
}

func (r *desktopResolver) createClient(ctx context.Context, account string) (*opresolver.Resolver, error) {
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := make(chan desktopResolverResult, 1)
	factory := r.newDesktopResolver
	if factory == nil {
		factory = opresolver.NewDesktopResolver
	}
	go func() {
		resolver, err := factory(initCtx, opresolver.ClientOptions{
			Account:            account,
			IntegrationName:    "Agent Secret Broker",
			IntegrationVersion: "dev",
		})
		results <- desktopResolverResult{resolver: resolver, err: err}
	}()

	select {
	case result := <-results:
		if result.err != nil {
			return nil, result.err
		}
		return result.resolver, nil
	case <-initCtx.Done():
		return nil, fmt.Errorf(
			"create 1Password SDK client timed out after 30s: unlock or restart 1Password and confirm SDK desktop integration is enabled: %w",
			initCtx.Err(),
		)
	}
}

func (r *desktopResolver) finishClientInit(account string, init *desktopResolverInit, resolver *opresolver.Resolver, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err == nil {
		r.clients[account] = resolver
	}
	delete(r.inits, account)
	init.resolver = resolver
	init.err = err
	close(init.done)
}

func waitForClientInit(ctx context.Context, init *desktopResolverInit) (*opresolver.Resolver, error) {
	select {
	case <-init.done:
		return init.resolver, init.err
	default:
	}

	select {
	case <-init.done:
		return init.resolver, init.err
	case <-ctx.Done():
		return nil, fmt.Errorf("create 1Password resolver: %w", ctx.Err())
	}
}

func (r *desktopResolver) effectiveAccount(accountOverride string) string {
	if account := strings.TrimSpace(accountOverride); account != "" {
		return account
	}
	return r.account
}
