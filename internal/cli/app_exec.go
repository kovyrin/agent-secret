package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/execwrap"
	"github.com/kovyrin/agent-secret/internal/request"
)

type execDryRunOutput struct {
	SchemaVersion string            `json:"schema_version"`
	OK            bool              `json:"ok"`
	WouldPrompt   bool              `json:"would_prompt"`
	WouldSpawn    bool              `json:"would_spawn"`
	Request       execDryRunRequest `json:"request"`
	Notes         []string          `json:"notes"`
}

type execDryRunRequest struct {
	Reason                 string               `json:"reason"`
	Command                []string             `json:"command"`
	ResolvedExecutable     string               `json:"resolved_executable"`
	CWD                    string               `json:"cwd"`
	TTL                    string               `json:"ttl"`
	EnvironmentFingerprint string               `json:"environment_fingerprint"`
	Secrets                []request.SecretSpec `json:"secrets"`
	OverrideEnv            bool                 `json:"override_env"`
	OverriddenAliases      []string             `json:"overridden_aliases,omitempty"`
	ForceRefresh           bool                 `json:"force_refresh"`
	ReuseOnly              bool                 `json:"reuse_only"`
}

func (a App) runExec(ctx context.Context, command Command) int {
	if command.ExecDryRun {
		return a.runExecDryRun(command)
	}
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

func (a App) runExecDryRun(command Command) int {
	req := command.ExecRequest
	output := execDryRunOutput{
		SchemaVersion: "1",
		OK:            true,
		WouldPrompt:   !req.ReuseOnly,
		WouldSpawn:    false,
		Request: execDryRunRequest{
			Reason:                 req.Reason,
			Command:                req.Command,
			ResolvedExecutable:     req.ResolvedExecutable,
			CWD:                    req.CWD,
			TTL:                    req.TTL.String(),
			EnvironmentFingerprint: req.EnvironmentFingerprint,
			Secrets:                dryRunSecrets(req.Secrets),
			OverrideEnv:            req.OverrideEnv,
			OverriddenAliases:      req.OverriddenAliases,
			ForceRefresh:           req.ForceRefresh,
			ReuseOnly:              req.ReuseOnly,
		},
		Notes: []string{
			"validated request locally",
			"did not start the daemon",
			"did not prompt for approval",
			"did not resolve or print secret values",
			"did not spawn the child command",
		},
	}
	if command.OutputJSON {
		if err := a.writeJSON(output); err != nil {
			a.stderrf("agent-secret: write exec dry-run json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutln("agent-secret exec dry run: ok")
	a.stdoutf("would prompt: %t\n", output.WouldPrompt)
	a.stdoutf("would spawn: %t\n", output.WouldSpawn)
	a.stdoutf("reason: %s\n", req.Reason)
	a.stdoutf("cwd: %s\n", req.CWD)
	a.stdoutf("command: %s\n", shellQuoteArgs(req.Command))
	a.stdoutf("ttl: %s\n", req.TTL)
	a.stdoutln("secrets:")
	for _, secret := range req.Secrets {
		account := secret.Account
		if account == "" {
			account = "(default desktop account)"
		}
		a.stdoutf("  %s=%s account=%s\n", secret.Alias, secret.Ref.Raw, account)
	}
	return 0
}

func dryRunSecrets(secrets []request.Secret) []request.SecretSpec {
	out := make([]request.SecretSpec, 0, len(secrets))
	for _, secret := range secrets {
		out = append(out, request.SecretSpec{
			Alias:   secret.Alias,
			Ref:     secret.Ref.Raw,
			Account: secret.Account,
		})
	}
	return out
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
		protocolErr.Code == protocol.ErrorCodeAuditFailed ||
		protocolErr.Code == protocol.ErrorCodeBadEnvelope ||
		protocolErr.Code == protocol.ErrorCodeBadType ||
		protocolErr.Code == protocol.ErrorCodeInvalidNonce ||
		protocolErr.Code == protocol.ErrorCodeRequestActive ||
		protocolErr.Code == protocol.ErrorCodeRequestExpired ||
		protocolErr.Code == protocol.ErrorCodeStaleApproval ||
		protocolErr.Code == protocol.ErrorCodeUntrustedClient
}

func shellQuoteArgs(args []string) string {
	var out strings.Builder
	for index, arg := range args {
		if index > 0 {
			out.WriteByte(' ')
		}
		out.WriteString(shellSingleQuote(arg))
	}
	return out.String()
}
