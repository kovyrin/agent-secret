package cli

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/execwrap"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
)

type sessionCreateOutput struct {
	SchemaVersion  string                     `json:"schema_version"`
	SessionID      string                     `json:"session_id"`
	SessionToken   string                     `json:"session_token"`
	SecretAliases  []string                   `json:"secret_aliases"`
	ExpiresAt      time.Time                  `json:"expires_at"`
	MaxReads       int                        `json:"max_reads"`
	RemainingReads int                        `json:"remaining_reads"`
	Binding        request.SessionBindingInfo `json:"session_binding"`
}

type sessionListOutput struct {
	SchemaVersion string                        `json:"schema_version"`
	Sessions      []protocol.SessionInfoPayload `json:"sessions"`
}

func (a App) runSessionCreate(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize background helper manager: %v\n", err)
		return 1
	}
	if err := a.ensureBackgroundHelper(ctx, manager); err != nil {
		a.stderrf("agent-secret: %s\n", backgroundHelperError(err))
		return 1
	}
	correlation, err := a.newCorrelation()
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	client, payload, err := a.requestSessionCreate(ctx, manager, correlation, command.SessionCreateRequest)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	output := sessionCreateOutput{
		SchemaVersion:  "1",
		SessionID:      payload.SessionID,
		SessionToken:   payload.SessionToken,
		SecretAliases:  payload.SecretAliases,
		ExpiresAt:      payload.ExpiresAt,
		MaxReads:       payload.MaxReads,
		RemainingReads: payload.RemainingReads,
		Binding:        payload.Binding,
	}
	if command.OutputJSON {
		if err := a.writeJSONMode(output, command.jsonOutputMode()); err != nil {
			a.stderrf("agent-secret: write session create json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutf("session id: %s\n", payload.SessionID)
	a.stdoutf("session token: %s\n", payload.SessionToken)
	a.stdoutf("expires: %s\n", payload.ExpiresAt.Format(time.RFC3339))
	a.stdoutf("reads: %d/%d remaining\n", payload.RemainingReads, payload.MaxReads)
	a.stdoutf("secrets: %s\n", strings.Join(payload.SecretAliases, ", "))
	if payload.Binding.BoundProcess.PID != 0 || payload.Binding.BoundProcess.Name != "" {
		a.stdoutf("bound process: %s pid=%d path=%s\n", payload.Binding.BoundProcess.Name, payload.Binding.BoundProcess.PID, payload.Binding.BoundProcess.Path)
	}
	return 0
}

func (a App) runSessionList(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize background helper manager: %v\n", err)
		return 1
	}
	if err := a.ensureBackgroundHelper(ctx, manager); err != nil {
		a.stderrf("agent-secret: %s\n", backgroundHelperError(err))
		return 1
	}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.SessionListResponsePayload, error) {
		return client.ListSessions(ctx)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSONMode(sessionListOutput{SchemaVersion: "1", Sessions: payload.Sessions}, command.jsonOutputMode()); err != nil {
			a.stderrf("agent-secret: write session list json: %v\n", err)
			return 1
		}
		return 0
	}
	if len(payload.Sessions) == 0 {
		a.stdoutln("no active sessions")
		return 0
	}
	for _, session := range payload.Sessions {
		a.stdoutf(
			"%s expires=%s reads=%d/%d cwd=%s secrets=%s reason=%s\n",
			session.SessionID,
			session.ExpiresAt.Format(time.RFC3339),
			session.RemainingReads,
			session.MaxReads,
			session.CWD,
			strings.Join(session.SecretAliases, ","),
			session.Reason,
		)
		if session.Binding.BoundProcess.PID != 0 || session.Binding.BoundProcess.Name != "" {
			a.stdoutf(
				"  bound=%s pid=%d path=%s\n",
				session.Binding.BoundProcess.Name,
				session.Binding.BoundProcess.PID,
				session.Binding.BoundProcess.Path,
			)
		}
	}
	return 0
}

func (a App) runSessionDestroy(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize background helper manager: %v\n", err)
		return 1
	}
	if err := a.ensureBackgroundHelper(ctx, manager); err != nil {
		a.stderrf("agent-secret: %s\n", backgroundHelperError(err))
		return 1
	}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.SessionDestroyResponsePayload, error) {
		return client.DestroySession(ctx, command.SessionDestroyRequest)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSONMode(payload, command.jsonOutputMode()); err != nil {
			a.stderrf("agent-secret: write session destroy json: %v\n", err)
			return 1
		}
		return 0
	}
	if command.SessionDestroyRequest.All {
		a.stdoutf("destroyed sessions: %d\n", payload.DestroyedCount)
		return 0
	}
	a.stdoutf("destroyed session: %s\n", payload.SessionID)
	return 0
}

func (a App) runWithSession(ctx context.Context, command Command) int {
	if err := os.Chdir(command.SessionResolveRequest.CWD); err != nil {
		a.stderrf("agent-secret: enter session cwd: %v\n", err)
		return 1
	}
	expectedPeer, err := peercred.CurrentExpected()
	if err != nil {
		a.stderrf("agent-secret: inspect current peer metadata: %v\n", err)
		return 1
	}
	req := command.SessionResolveRequest.WithExpectedPeer(expectedPeer)
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize background helper manager: %v\n", err)
		return 1
	}
	if err := a.ensureBackgroundHelper(ctx, manager); err != nil {
		a.stderrf("agent-secret: %s\n", backgroundHelperError(err))
		return 1
	}
	correlation, err := a.newCorrelation()
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	client, payload, err := a.requestSessionResolve(ctx, manager, correlation, req)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()

	interrupts := make(chan os.Signal, 2)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)

	reporter := daemonAuditReporter{
		client:      client,
		correlation: correlation,
		stderr:      a.Stderr,
	}
	result, err := execwrap.Run(ctx, execwrap.Spec{
		Path:         req.ResolvedExecutable,
		PathIdentity: req.ExecutableIdentity,
		Args:         req.Command[1:],
		Dir:          req.CWD,
		BaseEnv:      command.SessionEnv,
		Env:          payload.Env,
		OverrideEnv:  payload.OverrideEnv,
		Stdout:       a.Stdout,
		Stderr:       a.Stderr,
		Lifecycle:    reporter,
	}, interrupts)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	return result.ExitCode
}

func (a App) requestSessionCreate(
	ctx context.Context,
	manager daemonManager,
	correlation protocol.Correlation,
	req request.SessionCreateRequest,
) (daemonClient, protocol.SessionCreateResponsePayload, error) {
	return requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.SessionCreateResponsePayload, error) {
		return client.CreateSession(ctx, correlation, req)
	})
}

func (a App) requestSessionResolve(
	ctx context.Context,
	manager daemonManager,
	correlation protocol.Correlation,
	req request.SessionResolveRequest,
) (daemonClient, protocol.SessionResolveResponsePayload, error) {
	return requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.SessionResolveResponsePayload, error) {
		return client.ResolveSession(ctx, correlation, req)
	})
}

func (a App) newCorrelation() (protocol.Correlation, error) {
	requestID, err := a.randomID("req")
	if err != nil {
		return protocol.Correlation{}, err
	}
	nonce, err := a.randomID("nonce")
	if err != nil {
		return protocol.Correlation{}, err
	}
	return protocol.Correlation{RequestID: requestID, Nonce: nonce}, nil
}
