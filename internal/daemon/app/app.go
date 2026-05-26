package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/buildinfo"
	"github.com/kovyrin/agent-secret/internal/bwsm"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/gcpauth"
	"github.com/kovyrin/agent-secret/internal/gcpcompat"
	"github.com/kovyrin/agent-secret/internal/opresolver"
	"github.com/kovyrin/agent-secret/internal/processhardening"
	"github.com/kovyrin/agent-secret/internal/providerresolver"
)

func Run(args []string, stderr io.Writer) int {
	if err := processhardening.DisableCoreDumps(); err != nil {
		stderrf(stderr, "agent-secretd: harden process: %v\n", err)
		return 1
	}

	config, err := parseConfig(args)
	if err != nil {
		stderrf(stderr, "agent-secretd: parse flags: %v\n", err)
		return 2
	}

	auditWriter, err := audit.OpenDefault(nil)
	if err != nil {
		stderrf(stderr, "agent-secretd: open audit log: %v\n", err)
		return 1
	}
	defer func() { _ = auditWriter.Close() }()

	approver, err := approval.NewSocketApprover(
		config.socketPath,
		approval.ProcessApproverLauncher{},
		nil,
	)
	if err != nil {
		stderrf(stderr, "agent-secretd: initialize approver: %v\n", err)
		return 1
	}
	if err := gcpcompat.CleanupStale(gcpcompat.DefaultBaseDir()); err != nil {
		stderrf(stderr, "agent-secretd: clean stale GCP token files: %v\n", err)
		return 1
	}
	gcpStore := gcpauth.NewKeychainStore("")
	gcpAuth, err := gcpauth.NewService(gcpauth.ServiceOptions{
		Store: gcpStore,
		OAuth: gcpauth.NewOAuthFlow(gcpauth.OAuthFlowOptions{
			ClientID:     config.gcpOAuthClientID,
			ClientSecret: config.gcpOAuthClientSecret,
		}),
	})
	if err != nil {
		stderrf(stderr, "agent-secretd: initialize GCP auth service: %v\n", err)
		return 1
	}
	var gcpMinter daemonbroker.GCPTokenMinter
	if config.gcpOAuthClientID != "" {
		iamMinter, err := gcpauth.NewIAMCredentialsMinter(gcpauth.IAMCredentialsMinterOptions{
			Store:        gcpStore,
			ClientID:     config.gcpOAuthClientID,
			ClientSecret: config.gcpOAuthClientSecret,
		})
		if err != nil {
			stderrf(stderr, "agent-secretd: initialize GCP token minter: %v\n", err)
			return 1
		}
		gcpMinter = daemonGCPMinter{minter: iamMinter}
	}

	broker, err := daemonbroker.New(daemonbroker.Options{
		Approver: approver,
		Resolver: providerresolver.New(
			opresolver.NewDesktopPool(),
			bwsm.NewResolver(bwsm.NewKeychainStore("")),
		),
		GCPTokenMinter: gcpMinter,
		Audit:          auditWriter,
	})
	if err != nil {
		stderrf(stderr, "agent-secretd: initialize broker: %v\n", err)
		return 1
	}
	defaultClientPaths, err := peertrust.DefaultClientPaths()
	if err != nil {
		stderrf(stderr, "agent-secretd: discover trusted clients: %v\n", err)
		return 1
	}
	selfCheck, err := daemon.CurrentExecutableSelfCheck()
	if err != nil {
		stderrf(stderr, "agent-secretd: initialize executable self-check: %v\n", err)
		return 1
	}
	server, err := daemon.NewServer(daemon.ServerOptions{
		Broker:           broker,
		Approvals:        approver,
		ClientValidator:  peertrust.NewExecutableValidator(defaultClientPaths),
		OnePasswordCheck: onePasswordDesktopIntegrationCheck(),
		GCPAuth:          gcpAuth,
		SelfCheck:        selfCheck,
	})
	if err != nil {
		stderrf(stderr, "agent-secretd: initialize server: %v\n", err)
		return 1
	}
	if err := server.ListenAndServe(context.Background(), config.socketPath); err != nil {
		stderrf(stderr, "agent-secretd: %v\n", err)
		return 1
	}
	return 0
}

func onePasswordDesktopIntegrationCheck() func(context.Context, string) error {
	return func(ctx context.Context, accountName string) error {
		_, err := opresolver.NewDesktopResolver(ctx, opresolver.ClientOptions{
			Account:            accountName,
			IntegrationName:    "Agent Secret Doctor",
			IntegrationVersion: "dev",
		})
		return err
	}
}

type config struct {
	socketPath           string
	gcpOAuthClientID     string
	gcpOAuthClientSecret string
}

type daemonGCPMinter struct {
	minter *gcpauth.IAMCredentialsMinter
}

func (m daemonGCPMinter) MintAccessToken(ctx context.Context, req daemonbroker.GCPMintRequest) (gcpcompat.Token, error) {
	return m.minter.MintAccessToken(ctx, gcpauth.MintRequest{
		GoogleAccount:  req.GoogleAccount,
		Project:        req.Project,
		ServiceAccount: req.ServiceAccount,
		Scopes:         req.Scopes,
		Lifetime:       req.Lifetime,
		Reason:         req.Reason,
	})
}

func parseConfig(args []string) (config, error) {
	socketPath, err := socket.DefaultPath()
	if err != nil {
		return config{}, fmt.Errorf("resolve default socket path: %w", err)
	}

	parsed := config{}
	flags := flag.NewFlagSet("agent-secretd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&parsed.socketPath, "socket", socketPath, "daemon socket path")
	defaultClientID := strings.TrimSpace(os.Getenv("AGENT_SECRET_GCP_OAUTH_CLIENT_ID"))
	if defaultClientID == "" {
		defaultClientID = strings.TrimSpace(buildinfo.GCPOAuthClientID)
	}
	defaultClientSecret := strings.TrimSpace(os.Getenv("AGENT_SECRET_GCP_OAUTH_CLIENT_SECRET"))
	if defaultClientSecret == "" {
		defaultClientSecret = strings.TrimSpace(buildinfo.GCPOAuthClientSecret)
	}
	flags.StringVar(&parsed.gcpOAuthClientID, "gcp-oauth-client-id", defaultClientID, "GCP OAuth desktop client ID")
	parsed.gcpOAuthClientSecret = defaultClientSecret
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	return parsed, nil
}

func stderrf(stderr io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(stderr, format, args...)
}
