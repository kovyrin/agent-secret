package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/opresolver"
)

func main() {
	os.Exit(run())
}

func run() int {
	socketPath, err := daemon.DefaultSocketPath()
	if err != nil {
		stderrf("agent-secretd: resolve default socket path: %v\n", err)
		return 1
	}

	flags := flag.NewFlagSet("agent-secretd", flag.ExitOnError)
	flags.StringVar(&socketPath, "socket", socketPath, "daemon socket path")
	approverPath := flags.String("approver", os.Getenv("AGENT_SECRET_APPROVER_PATH"), "approver executable or .app path")
	accountName := flags.String("account", os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT"), "1Password account sign-in address, name, or UUID; empty uses OP_ACCOUNT or my.1password.com")
	if err := flags.Parse(os.Args[1:]); err != nil {
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
		socketPath,
		daemon.ProcessApproverLauncher{AppPath: *approverPath},
		nil,
	)
	if err != nil {
		stderrf("agent-secretd: initialize approver: %v\n", err)
		return 1
	}

	broker, err := daemon.NewBroker(daemon.BrokerOptions{
		Approver: approver,
		Resolver: newResolver(*accountName),
		Audit:    auditWriter,
	})
	if err != nil {
		stderrf("agent-secretd: initialize broker: %v\n", err)
		return 1
	}
	server, err := daemon.NewServer(daemon.ServerOptions{Broker: broker, Approvals: approver})
	if err != nil {
		stderrf("agent-secretd: initialize server: %v\n", err)
		return 1
	}
	if err := server.ListenAndServe(context.Background(), socketPath); err != nil {
		stderrf("agent-secretd: %v\n", err)
		return 1
	}
	return 0
}

func stderrf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format, args...)
}

type desktopResolver struct {
	mu       sync.Mutex
	account  string
	resolver *opresolver.Resolver
}

type desktopResolverResult struct {
	resolver *opresolver.Resolver
	err      error
}

func newResolver(account string) daemon.Resolver {
	account = strings.TrimSpace(account)
	return &desktopResolver{account: account}
}

func (r *desktopResolver) Resolve(ctx context.Context, ref string) (string, error) {
	resolver, err := r.client(ctx)
	if err != nil {
		return "", fmt.Errorf("create 1Password resolver: %w", err)
	}
	secret, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve secret: %w", err)
	}
	return secret.Value(), nil
}

func (r *desktopResolver) client(ctx context.Context) (*opresolver.Resolver, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resolver != nil {
		return r.resolver, nil
	}

	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := make(chan desktopResolverResult, 1)
	go func() {
		resolver, err := opresolver.NewDesktopResolver(initCtx, opresolver.ClientOptions{
			Account:            r.account,
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
		r.resolver = result.resolver
		return r.resolver, nil
	case <-initCtx.Done():
		return nil, fmt.Errorf(
			"create 1Password SDK client timed out after 30s: unlock or restart 1Password and confirm SDK desktop integration is enabled: %w",
			initCtx.Err(),
		)
	}
}
