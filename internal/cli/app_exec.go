package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/execwrap"
	"github.com/kovyrin/agent-secret/internal/request"
)

func (a App) runExec(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	requestID, err := a.randomID("req")
	if err != nil {
		a.stderrf("agent-secret: generate request id: %v\n", err)
		return 1
	}
	nonce, err := a.randomID("nonce")
	if err != nil {
		a.stderrf("agent-secret: generate request nonce: %v\n", err)
		return 1
	}
	correlation := protocol.Correlation{RequestID: requestID, Nonce: nonce}
	client, payload, err := a.requestExec(ctx, manager, correlation, command.ExecRequest)
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
		Path:         command.ExecRequest.ResolvedExecutable,
		PathIdentity: command.ExecRequest.ExecutableIdentity,
		Args:         command.ExecRequest.Command[1:],
		Dir:          command.ExecRequest.CWD,
		BaseEnv:      command.ExecEnv,
		Env:          payload.Env,
		OverrideEnv:  command.ExecRequest.OverrideEnv,
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

func (a App) requestExec(
	ctx context.Context,
	manager daemonManager,
	correlation protocol.Correlation,
	req request.ExecRequest,
) (daemonClient, protocol.ExecResponsePayload, error) {
	return requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.ExecResponsePayload, error) {
		return client.RequestExec(ctx, correlation, req)
	})
}

type daemonAuditReporter struct {
	client      daemonClient
	correlation protocol.Correlation
	stderr      io.Writer
}

func (r daemonAuditReporter) CommandStarted(ctx context.Context, childPID int) error {
	if err := r.client.ReportStarted(ctx, r.correlation, childPID); err != nil {
		if isFatalCommandStartedAuditFailure(err) {
			return err
		}
		_, _ = fmt.Fprintf(
			r.stderr,
			"agent-secret: warning: daemon disconnected after child start; command_started audit was not recorded: %v\n",
			err,
		)
	}
	return nil
}

func (r daemonAuditReporter) CommandCompleted(ctx context.Context, result execwrap.Result) error {
	signal := ""
	if result.Signal != nil {
		signal = result.Signal.String()
	}
	if err := r.client.ReportCompleted(ctx, r.correlation, result.ExitCode, signal); err != nil {
		_, _ = fmt.Fprintf(r.stderr, "agent-secret: warning: daemon completion audit was not recorded: %v\n", err)
	}
	return nil
}

func isFatalCommandStartedAuditFailure(err error) bool {
	if errors.Is(err, protocol.ErrInvalidNonce) ||
		errors.Is(err, protocol.ErrMalformedEnvelope) ||
		errors.Is(err, protocol.ErrProtocolType) {
		return true
	}

	var protocolErr *control.ProtocolError
	if !errors.As(err, &protocolErr) {
		return false
	}
	return protocolErr.Code == protocol.ErrorCodeBadCommandStarted ||
		protocolErr.Code == protocol.ErrorCodeBadEnvelope ||
		protocolErr.Code == protocol.ErrorCodeBadType ||
		protocolErr.Code == protocol.ErrorCodeInvalidNonce ||
		protocolErr.Code == protocol.ErrorCodeRequestActive ||
		protocolErr.Code == protocol.ErrorCodeRequestExpired ||
		protocolErr.Code == protocol.ErrorCodeStaleApproval ||
		protocolErr.Code == protocol.ErrorCodeUntrustedClient
}
