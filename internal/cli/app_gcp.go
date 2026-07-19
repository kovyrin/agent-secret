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
	"github.com/kovyrin/agent-secret/internal/fileidentity"
)

type gcpExecDryRunOutput struct {
	SchemaVersion string               `json:"schema_version"`
	OK            bool                 `json:"ok"`
	WouldPrompt   bool                 `json:"would_prompt"`
	WouldSpawn    bool                 `json:"would_spawn"`
	Request       gcpExecDryRunRequest `json:"request"`
	Notes         []string             `json:"notes"`
}

type gcpExecDryRunRequest struct {
	Reason                 string   `json:"reason"`
	Command                []string `json:"command"`
	ResolvedExecutable     string   `json:"resolved_executable"`
	AllowMutableExecutable bool     `json:"allow_mutable_executable"`
	CWD                    string   `json:"cwd"`
	TTL                    string   `json:"ttl"`
	EnvironmentFingerprint string   `json:"environment_fingerprint"`
	GoogleAccount          string   `json:"google_account"`
	Project                string   `json:"project"`
	ServiceAccount         string   `json:"service_account"`
	Scopes                 []string `json:"scopes"`
	ProfileName            string   `json:"profile_name,omitempty"`
	ConfigRoot             string   `json:"config_root,omitempty"`
	DeliveryMode           string   `json:"delivery_mode"`
	ReuseOnly              bool     `json:"reuse_only"`
}

type gcpSessionCreateOutput struct {
	SchemaVersion          string `json:"schema_version"`
	SessionHandle          string `json:"session_handle"`
	SessionAuditID         string `json:"session_audit_id"`
	ExpiresAt              string `json:"expires_at"`
	RemainingCommandStarts int    `json:"remaining_command_starts"`
}

type gcpSessionListOutput struct {
	SchemaVersion string                    `json:"schema_version"`
	Sessions      []protocol.GCPSessionInfo `json:"sessions"`
}

type gcpSessionDestroyOutput struct {
	SchemaVersion  string `json:"schema_version"`
	Destroyed      bool   `json:"destroyed"`
	SessionAuditID string `json:"session_audit_id,omitempty"`
}

type gcpAuthStatusOutput struct {
	SchemaVersion string                        `json:"schema_version"`
	Accounts      []protocol.GCPAuthAccountInfo `json:"accounts"`
}

type gcpAuthLoginOutput struct {
	SchemaVersion string                      `json:"schema_version"`
	Account       protocol.GCPAuthAccountInfo `json:"account"`
}

type gcpAuthLogoutOutput struct {
	SchemaVersion string `json:"schema_version"`
	GoogleAccount string `json:"google_account"`
	Deleted       bool   `json:"deleted"`
}

const gcpAuthLoginTimeout = 5 * time.Minute

func (a App) runGCPExec(ctx context.Context, command Command) int {
	if command.GCPDryRun {
		return a.runGCPExecDryRun(command)
	}
	return a.runGCPCommand(ctx, command.GCPEnv, command.GCPExecRequest.ResolvedExecutable, command.GCPExecRequest.ExecutableIdentity, command.GCPExecRequest.Command, command.GCPExecRequest.CWD, func(client daemonClient, correlation protocol.Correlation) (protocol.GCPCommandResponsePayload, error) {
		return client.RequestGCPExec(ctx, correlation, command.GCPExecRequest)
	})
}

func (a App) runGCPWithSession(ctx context.Context, command Command) int {
	req := command.GCPSessionUseRequest
	return a.runGCPCommand(ctx, command.GCPEnv, req.ResolvedExecutable, req.ExecutableIdentity, req.Command, req.CWD, func(client daemonClient, correlation protocol.Correlation) (protocol.GCPCommandResponsePayload, error) {
		return client.UseGCPSession(ctx, correlation, req)
	})
}

func (a App) runGCPCommand(
	ctx context.Context,
	baseEnv []string,
	resolvedExecutable string,
	executableIdentity fileidentity.Identity,
	command []string,
	cwd string,
	requestPayload func(daemonClient, protocol.Correlation) (protocol.GCPCommandResponsePayload, error),
) int {
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
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.GCPCommandResponsePayload, error) {
		return requestPayload(client, correlation)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()

	interrupts := make(chan os.Signal, 2)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)

	reporter := daemonAuditReporter{client: client, correlation: correlation, stderr: a.Stderr}
	result, err := execwrap.Run(ctx, execwrap.Spec{
		Path:         resolvedExecutable,
		PathIdentity: executableIdentity,
		Args:         command[1:],
		Dir:          cwd,
		BaseEnv:      baseEnv,
		Env:          payload.Env,
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

func (a App) runGCPExecDryRun(command Command) int {
	req := command.GCPExecRequest
	output := gcpExecDryRunOutput{
		SchemaVersion: "1",
		OK:            true,
		WouldPrompt:   !req.ReuseOnly,
		WouldSpawn:    false,
		Request: gcpExecDryRunRequest{
			Reason:                 req.Reason,
			Command:                req.Command,
			ResolvedExecutable:     req.ResolvedExecutable,
			AllowMutableExecutable: req.AllowMutableExecutable,
			CWD:                    req.CWD,
			TTL:                    req.TTL.String(),
			EnvironmentFingerprint: req.EnvironmentFingerprint,
			GoogleAccount:          req.GoogleAccount,
			Project:                req.Project,
			ServiceAccount:         req.ServiceAccount,
			Scopes:                 req.Scopes,
			ProfileName:            req.ProfileName,
			ConfigRoot:             req.ConfigRoot,
			DeliveryMode:           req.DeliveryMode,
			ReuseOnly:              req.ReuseOnly,
		},
		Notes: []string{
			"validated request locally",
			"did not start the daemon",
			"did not prompt for approval",
			"did not mint or print GCP tokens",
			"did not spawn the child command",
		},
	}
	if command.OutputJSON {
		if err := a.writeJSON(output); err != nil {
			a.stderrf("agent-secret: write gcp exec dry-run json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutln("agent-secret gcp exec dry run: ok")
	a.stdoutf("would prompt: %t\n", output.WouldPrompt)
	a.stdoutf("would spawn: %t\n", output.WouldSpawn)
	a.stdoutf("reason: %s\n", req.Reason)
	a.stdoutf("cwd: %s\n", req.CWD)
	a.stdoutf("command: %s\n", shellQuoteArgs(req.Command))
	a.stdoutf("allow_mutable_executable: %t\n", req.AllowMutableExecutable)
	a.stdoutf("ttl: %s\n", req.TTL)
	a.stdoutf("google_account: %s\n", req.GoogleAccount)
	a.stdoutf("project: %s\n", req.Project)
	a.stdoutf("service_account: %s\n", req.ServiceAccount)
	a.stdoutf("scopes: %s\n", strings.Join(req.Scopes, ", "))
	return 0
}

func (a App) runGCPSessionCreate(ctx context.Context, command Command) int {
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
	handle, err := a.randomID("asess")
	if err != nil {
		a.stderrf("agent-secret: generate session handle: %v\n", err)
		return 1
	}
	correlation := protocol.Correlation{RequestID: requestID, Nonce: nonce}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.GCPSessionCreateResponsePayload, error) {
		return client.CreateGCPSession(ctx, correlation, command.GCPSessionCreateRequest, handle)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()

	if command.OutputJSON {
		if err := a.writeJSON(gcpSessionCreateOutput{
			SchemaVersion:          "1",
			SessionHandle:          payload.SessionHandle,
			SessionAuditID:         payload.SessionAuditID,
			ExpiresAt:              payload.ExpiresAt.Format(time.RFC3339Nano),
			RemainingCommandStarts: payload.RemainingCommandStarts,
		}); err != nil {
			a.stderrf("agent-secret: write gcp session create json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutf("gcp session: %s\n", payload.SessionHandle)
	a.stdoutf("expires_at: %s\n", payload.ExpiresAt.Format(time.RFC3339Nano))
	a.stdoutf("remaining_command_starts: %d\n", payload.RemainingCommandStarts)
	return 0
}

func (a App) runGCPSessionList(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	cwd, err := normalizeCWD("")
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.GCPSessionListResponsePayload, error) {
		return client.ListGCPSessions(ctx, cwd)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSON(gcpSessionListOutput{SchemaVersion: "1", Sessions: payload.Sessions}); err != nil {
			a.stderrf("agent-secret: write gcp session list json: %v\n", err)
			return 1
		}
		return 0
	}
	if len(payload.Sessions) == 0 {
		a.stdoutln("gcp sessions: none")
		return 0
	}
	for _, session := range payload.Sessions {
		usable := "not usable from cwd"
		if session.UsableFromCWD {
			usable = "usable from cwd"
		}
		a.stdoutf("%s %s project=%s service_account=%s remaining_starts=%d %s\n",
			session.SessionAuditID,
			session.ProfileName,
			session.Project,
			session.ServiceAccount,
			session.RemainingCommandStarts,
			usable,
		)
	}
	return 0
}

func (a App) runGCPSessionDestroy(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.GCPSessionDestroyResponsePayload, error) {
		return client.DestroyGCPSession(ctx, command.GCPSessionDestroyRequest)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSON(gcpSessionDestroyOutput{SchemaVersion: "1", Destroyed: payload.Destroyed, SessionAuditID: payload.SessionAuditID}); err != nil {
			a.stderrf("agent-secret: write gcp session destroy json: %v\n", err)
			return 1
		}
		return 0
	}
	if payload.Destroyed {
		a.stdoutln("gcp session: destroyed")
	} else {
		a.stdoutln("gcp session: not found")
	}
	return 0
}

func (a App) runGCPAuth(ctx context.Context, command Command) int {
	//nolint:exhaustive // This helper is called only for gcp auth command kinds.
	switch command.Kind {
	case KindGCPAuthStatus:
		return a.runGCPAuthStatus(ctx, command)
	case KindGCPAuthLogin:
		return a.runGCPAuthLogin(ctx, command)
	case KindGCPAuthLogout:
		return a.runGCPAuthLogout(ctx, command)
	}
	return 0
}

func (a App) runGCPAuthStatus(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.GCPAuthStatusResponsePayload, error) {
		return client.GCPAuthStatus(ctx, command.GCPAuthStatusRequest)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSON(gcpAuthStatusOutput{SchemaVersion: "1", Accounts: payload.Accounts}); err != nil {
			a.stderrf("agent-secret: write gcp auth status json: %v\n", err)
			return 1
		}
		return 0
	}
	if len(payload.Accounts) == 0 {
		a.stdoutln("gcp auth: no bootstrap accounts configured")
		return 0
	}
	for _, account := range payload.Accounts {
		a.stdoutf("%s email=%s scopes=%s updated_at=%s\n",
			account.GoogleAccount,
			account.Email,
			strings.Join(account.Scopes, ","),
			account.UpdatedAt.Format(time.RFC3339Nano),
		)
	}
	return 0
}

func (a App) runGCPAuthLogin(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	loginCtx, cancel := context.WithTimeout(ctx, gcpAuthLoginTimeout)
	defer cancel()
	client, payload, err := requestDaemonPayload(loginCtx, manager, func(client daemonClient) (protocol.GCPAuthLoginResponsePayload, error) {
		return client.GCPAuthLogin(loginCtx, command.GCPAuthLoginRequest)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSON(gcpAuthLoginOutput{SchemaVersion: "1", Account: payload.Account}); err != nil {
			a.stderrf("agent-secret: write gcp auth login json: %v\n", err)
			return 1
		}
		return 0
	}
	a.stdoutln("gcp auth: logged in")
	a.stdoutf("google_account: %s\n", payload.Account.GoogleAccount)
	a.stdoutf("email: %s\n", payload.Account.Email)
	return 0
}

func (a App) runGCPAuthLogout(ctx context.Context, command Command) int {
	manager, err := a.daemonManager()
	if err != nil {
		a.stderrf("agent-secret: initialize daemon manager: %v\n", err)
		return 1
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	client, payload, err := requestDaemonPayload(ctx, manager, func(client daemonClient) (protocol.GCPAuthLogoutResponsePayload, error) {
		return client.GCPAuthLogout(ctx, command.GCPAuthLogoutRequest)
	})
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()
	if command.OutputJSON {
		if err := a.writeJSON(gcpAuthLogoutOutput{SchemaVersion: "1", GoogleAccount: payload.GoogleAccount, Deleted: payload.Deleted}); err != nil {
			a.stderrf("agent-secret: write gcp auth logout json: %v\n", err)
			return 1
		}
		return 0
	}
	if payload.Deleted {
		a.stdoutf("gcp auth: removed %s\n", payload.GoogleAccount)
	} else {
		a.stdoutf("gcp auth: %s was not configured\n", payload.GoogleAccount)
	}
	return 0
}
