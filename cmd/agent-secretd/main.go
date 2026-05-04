package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
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

	approver, err := approval.NewSocketApprover(
		config.socketPath,
		approval.ProcessApproverLauncher{},
		nil,
	)
	if err != nil {
		stderrf("agent-secretd: initialize approver: %v\n", err)
		return 1
	}

	broker, err := daemonbroker.New(daemonbroker.Options{
		Approver: approver,
		Resolver: opresolver.NewDesktopPool(config.accountName),
		Audit:    auditWriter,
	})
	if err != nil {
		stderrf("agent-secretd: initialize broker: %v\n", err)
		return 1
	}
	server, err := daemon.NewServer(daemon.ServerOptions{
		Broker:           broker,
		Approvals:        approver,
		ExecValidator:    peertrust.NewExecutableValidator(peertrust.DefaultClientPaths()),
		OnePasswordCheck: onePasswordDesktopIntegrationCheck(config.accountName),
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

func onePasswordDesktopIntegrationCheck(accountName string) func(context.Context) error {
	return func(ctx context.Context) error {
		_, err := opresolver.NewDesktopResolver(ctx, opresolver.ClientOptions{
			Account:            accountName,
			IntegrationName:    "Agent Secret Doctor",
			IntegrationVersion: "dev",
		})
		return err
	}
}

type daemonConfig struct {
	socketPath  string
	accountName string
}

func parseDaemonConfig(args []string) (daemonConfig, error) {
	socketPath, err := socket.DefaultPath()
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
