package cli

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	"github.com/kovyrin/agent-secret/internal/daemon/control"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/execwrap"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/opresolver"
	"github.com/kovyrin/agent-secret/internal/randid"
	"github.com/kovyrin/agent-secret/internal/request"
)

type App struct {
	Parser                 Parser
	InstallCLI             func(install.CLIOptions) (install.CLIResult, error)
	InstallSkill           func(install.SkillOptions) (install.SkillResult, error)
	RandomReader           io.Reader
	DoctorApproverCheck    func(context.Context) error
	DoctorOnePasswordCheck func(context.Context) error
	Stdout                 io.Writer
	Stderr                 io.Writer
	manager                daemonManager
}

type daemonManager interface {
	EnsureRunning(ctx context.Context) error
	Connect(ctx context.Context) (daemonClient, error)
	Status(ctx context.Context) (protocol.StatusPayload, error)
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	SocketPath() string
}

type daemonClient interface {
	Close() error
	RequestExec(
		ctx context.Context,
		correlation protocol.Correlation,
		req request.ExecRequest,
	) (protocol.ExecResponsePayload, error)
	ReportStarted(ctx context.Context, correlation protocol.Correlation, childPID int) error
	ReportCompleted(ctx context.Context, correlation protocol.Correlation, exitCode int, signal string) error
}

type daemonControlManager struct {
	manager control.Manager
}

func (m daemonControlManager) EnsureRunning(ctx context.Context) error {
	return m.manager.EnsureRunning(ctx)
}

func (m daemonControlManager) Connect(ctx context.Context) (daemonClient, error) {
	return m.manager.Connect(ctx)
}

func (m daemonControlManager) Status(ctx context.Context) (protocol.StatusPayload, error) {
	return m.manager.Status(ctx)
}

func (m daemonControlManager) Start(ctx context.Context) error {
	return m.manager.Start(ctx)
}

func (m daemonControlManager) Stop(ctx context.Context) error {
	return m.manager.Stop(ctx)
}

func (m daemonControlManager) SocketPath() string {
	return m.manager.SocketPath
}

func NewApp(manager control.Manager, stdout io.Writer, stderr io.Writer) App {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return App{
		Parser:                 NewParser(),
		InstallCLI:             install.InstallCLI,
		InstallSkill:           install.InstallSkill,
		RandomReader:           rand.Reader,
		DoctorApproverCheck:    checkApproverHealth,
		DoctorOnePasswordCheck: checkOnePasswordDesktopIntegration,
		Stdout:                 stdout,
		Stderr:                 stderr,
		manager:                daemonControlManager{manager: manager},
	}
}

func (a App) daemonManager() daemonManager {
	if a.manager != nil {
		return a.manager
	}
	return daemonControlManager{}
}

func (a App) Run(ctx context.Context, args []string) int {
	command, err := a.Parser.Parse(args)
	if errors.Is(err, ErrHelpRequested) {
		a.stdoutln(command.HelpText)
		return 0
	}
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 2
	}

	switch command.Kind {
	case KindHelp:
		a.stdoutln(command.HelpText)
		return 0
	case KindExec:
		return a.runExec(ctx, command)
	case KindDaemonStatus:
		return a.runDaemonStatus(ctx)
	case KindDaemonStart:
		return a.runDaemonStart(ctx)
	case KindDaemonStop:
		return a.runDaemonStop(ctx)
	case KindDoctor:
		return a.runDoctor(ctx)
	case KindInstallCLI:
		return a.runInstallCLI(command)
	case KindSkillInstall:
		return a.runSkillInstall(command)
	default:
		a.stderrf("agent-secret: unsupported command %s\n", command.Kind)
		return 2
	}
}

func (a App) runExec(ctx context.Context, command Command) int {
	manager := a.daemonManager()
	if err := manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	client, err := manager.Connect(ctx)
	if err != nil {
		a.stderrf("agent-secret: connect daemon: %v\n", err)
		return 1
	}
	defer func() { _ = client.Close() }()

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
	payload, err := client.RequestExec(ctx, correlation, command.ExecRequest)
	if err != nil {
		a.stderrf("agent-secret: request rejected: %v\n", err)
		return 1
	}

	interrupts := make(chan os.Signal, 2)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)

	reporter := daemonAuditReporter{
		client:      client,
		correlation: correlation,
		stderr:      a.Stderr,
	}
	result, err := execwrap.Run(ctx, execwrap.Spec{
		Path:                   command.ExecRequest.ResolvedExecutable,
		PathIdentity:           command.ExecRequest.ExecutableIdentity,
		Args:                   command.ExecRequest.Command[1:],
		Dir:                    command.ExecRequest.CWD,
		BaseEnv:                command.ExecRequest.Env,
		Env:                    payload.Env,
		OverrideEnv:            command.ExecRequest.OverrideEnv,
		AllowMutableExecutable: command.ExecRequest.AllowMutableExecutable,
		Stdout:                 a.Stdout,
		Stderr:                 a.Stderr,
		Lifecycle:              reporter,
	}, interrupts)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	return result.ExitCode
}

func (a App) runDaemonStatus(ctx context.Context) int {
	status, err := a.daemonManager().Status(ctx)
	if err != nil {
		a.stdoutf("agent-secretd: stopped (%v)\n", err)
		return 1
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStart(ctx context.Context) int {
	manager := a.daemonManager()
	if err := manager.Start(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	status, err := manager.Status(ctx)
	if err != nil {
		a.stderrf("agent-secret: daemon started but status failed: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStop(ctx context.Context) int {
	if err := a.daemonManager().Stop(ctx); err != nil {
		a.stderrf("agent-secret: stop daemon: %v\n", err)
		return 1
	}
	a.stdoutln("agent-secretd: stopped")
	return 0
}

func (a App) runDoctor(ctx context.Context) int {
	manager := a.daemonManager()
	healthy := true
	a.stdoutln("agent-secret doctor")
	a.stdoutf("platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	a.stdoutf("daemon socket: %s\n", manager.SocketPath())
	if auditPath, err := checkAuditLogWritable(ctx); err != nil {
		healthy = false
		if auditPath == "" {
			a.stdoutf("audit log: failed (%v)\n", err)
		} else {
			a.stdoutf("audit log: failed %s (%v)\n", auditPath, err)
		}
	} else {
		a.stdoutf("audit log: writable %s\n", auditPath)
	}
	if err := manager.EnsureRunning(ctx); err != nil {
		healthy = false
		a.stdoutf("daemon startup: failed (%v)\n", err)
	} else {
		a.stdoutln("daemon startup: ok")
	}
	if status, err := manager.Status(ctx); err == nil {
		a.stdoutf("daemon: running pid=%d\n", status.PID)
	} else {
		healthy = false
		a.stdoutf("daemon: failed (%v)\n", err)
	}
	if err := socket.ValidateSocketDirectoryForPath(manager.SocketPath()); err != nil {
		healthy = false
		a.stdoutf("socket directory: failed (%v)\n", err)
	} else {
		a.stdoutln("socket directory: private")
	}
	if check := a.DoctorApproverCheck; check != nil {
		if err := check(ctx); err != nil {
			healthy = false
			a.stdoutf("native approver: failed (%v)\n", err)
		} else {
			a.stdoutln("native approver: ok")
		}
	}
	if check := a.DoctorOnePasswordCheck; check != nil {
		if err := check(ctx); err != nil {
			healthy = false
			a.stdoutf("1password desktop integration: failed (%v)\n", err)
		} else {
			a.stdoutln("1password desktop integration: ok")
		}
	}
	if !healthy {
		return 1
	}
	return 0
}

func checkAuditLogWritable(ctx context.Context) (string, error) {
	path, err := audit.DefaultPath()
	if err != nil {
		return "", err
	}
	writer, err := audit.OpenDefault(nil)
	if err != nil {
		return path, err
	}
	defer func() { _ = writer.Close() }()
	if err := writer.Preflight(ctx); err != nil {
		return path, err
	}
	return path, nil
}

func checkApproverHealth(ctx context.Context) error {
	return (approval.ProcessApproverLauncher{}).CheckHealth(ctx)
}

func checkOnePasswordDesktopIntegration(ctx context.Context) error {
	_, err := opresolver.NewDesktopResolver(ctx, opresolver.ClientOptions{
		Account:            os.Getenv("AGENT_SECRET_1PASSWORD_ACCOUNT"),
		IntegrationName:    "Agent Secret Doctor",
		IntegrationVersion: "dev",
	})
	return err
}

func (a App) runInstallCLI(command Command) int {
	installCLI := a.InstallCLI
	if installCLI == nil {
		installCLI = install.InstallCLI
	}
	result, err := installCLI(command.InstallCLIOptions)
	if err != nil {
		a.stderrf("agent-secret: install-cli: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secret command installed: %s -> %s\n", result.LinkPath, result.TargetPath)
	return 0
}

func (a App) runSkillInstall(command Command) int {
	installSkill := a.InstallSkill
	if installSkill == nil {
		installSkill = install.InstallSkill
	}
	result, err := installSkill(command.InstallSkillOpts)
	if err != nil {
		a.stderrf("agent-secret: skill-install: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secret skill installed: %s -> %s\n", result.LinkPath, result.TargetPath)
	return 0
}

func (a App) stdoutf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.Stdout, format, args...)
}

func (a App) stdoutln(args ...any) {
	_, _ = fmt.Fprintln(a.Stdout, args...)
}

func (a App) stderrf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.Stderr, format, args...)
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
	switch protocolErr.Code {
	case protocol.ErrorCodeBadCommandStarted,
		protocol.ErrorCodeBadEnvelope,
		protocol.ErrorCodeBadType,
		protocol.ErrorCodeInvalidNonce,
		protocol.ErrorCodeRequestActive,
		protocol.ErrorCodeRequestExpired,
		protocol.ErrorCodeStaleApproval,
		protocol.ErrorCodeUntrustedClient:
		return true
	case protocol.ErrorCodeApprovalDenied,
		protocol.ErrorCodeApprovalUnavailable,
		protocol.ErrorCodeApproverIdentityMismatch,
		protocol.ErrorCodeApproverPeerMismatch,
		protocol.ErrorCodeAuditFailed,
		protocol.ErrorCodeBadApprovalDecision,
		protocol.ErrorCodeBadCommandCompleted,
		protocol.ErrorCodeBadRequest,
		protocol.ErrorCodeContextCanceled,
		protocol.ErrorCodeContextDeadlineExceeded,
		protocol.ErrorCodeDaemonStopped,
		protocol.ErrorCodeFrameTooLarge,
		protocol.ErrorCodeNoPendingApproval,
		protocol.ErrorCodePeerRejected,
		protocol.ErrorCodeRequestFailed,
		protocol.ErrorCodeResolveFailed:
		return false
	default:
		return false
	}
}

func (a App) randomID(prefix string) (string, error) {
	return randid.Generate(a.RandomReader, prefix)
}
