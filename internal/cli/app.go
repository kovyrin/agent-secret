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
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/execwrap"
	"github.com/kovyrin/agent-secret/internal/install"
	"github.com/kovyrin/agent-secret/internal/opresolver"
	"github.com/kovyrin/agent-secret/internal/randid"
)

type App struct {
	Parser                 Parser
	Manager                daemon.Manager
	InstallCLI             func(install.CLIOptions) (install.CLIResult, error)
	InstallSkill           func(install.SkillOptions) (install.SkillResult, error)
	RandomReader           io.Reader
	DoctorApproverCheck    func(context.Context) error
	DoctorOnePasswordCheck func(context.Context) error
	Stdout                 io.Writer
	Stderr                 io.Writer
}

func NewApp(manager daemon.Manager, stdout io.Writer, stderr io.Writer) App {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return App{
		Parser:                 NewParser(time.Now),
		Manager:                manager,
		InstallCLI:             install.InstallCLI,
		InstallSkill:           install.InstallSkill,
		RandomReader:           rand.Reader,
		DoctorApproverCheck:    checkApproverHealth,
		DoctorOnePasswordCheck: checkOnePasswordDesktopIntegration,
		Stdout:                 stdout,
		Stderr:                 stderr,
	}
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
	if err := a.Manager.EnsureRunning(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	client, err := a.Manager.Connect(ctx)
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
	payload, err := client.RequestExec(ctx, requestID, nonce, command.ExecRequest)
	if err != nil {
		a.stderrf("agent-secret: request rejected: %v\n", err)
		return 1
	}

	interrupts := make(chan os.Signal, 2)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(interrupts)

	reporter := daemonAuditReporter{
		client:    client,
		requestID: requestID,
		nonce:     nonce,
		stderr:    a.Stderr,
	}
	result, err := execwrap.Run(ctx, execwrap.Spec{
		Path:                   command.ExecRequest.ResolvedExecutable,
		PathIdentity:           command.ExecRequest.ExecutableIdentity,
		Args:                   command.ExecRequest.Command[1:],
		Dir:                    command.ExecRequest.CWD,
		BaseEnv:                command.ExecRequest.Env,
		Env:                    payload.Env,
		SecretAliases:          payload.SecretAliases,
		OverrideEnv:            command.ExecRequest.OverrideEnv,
		AllowMutableExecutable: command.ExecRequest.AllowMutableExecutable,
		Stdout:                 a.Stdout,
		Stderr:                 a.Stderr,
		Audit:                  reporter,
	}, interrupts)
	if err != nil {
		a.stderrf("agent-secret: %v\n", err)
		return 1
	}
	return result.ExitCode
}

func (a App) runDaemonStatus(ctx context.Context) int {
	status, err := a.Manager.Status(ctx)
	if err != nil {
		a.stdoutf("agent-secretd: stopped (%v)\n", err)
		return 1
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStart(ctx context.Context) int {
	if err := a.Manager.Start(ctx); err != nil {
		a.stderrf("agent-secret: start daemon: %v\n", err)
		return 1
	}
	status, err := a.Manager.Status(ctx)
	if err != nil {
		a.stderrf("agent-secret: daemon started but status failed: %v\n", err)
		return 1
	}
	a.stdoutf("agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStop(ctx context.Context) int {
	if err := a.Manager.Stop(ctx); err != nil {
		a.stderrf("agent-secret: stop daemon: %v\n", err)
		return 1
	}
	a.stdoutln("agent-secretd: stopped")
	return 0
}

func (a App) runDoctor(ctx context.Context) int {
	healthy := true
	a.stdoutln("agent-secret doctor")
	a.stdoutf("platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	a.stdoutf("daemon socket: %s\n", a.Manager.SocketPath)
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
	if err := a.Manager.EnsureRunning(ctx); err != nil {
		healthy = false
		a.stdoutf("daemon startup: failed (%v)\n", err)
	} else {
		a.stdoutln("daemon startup: ok")
	}
	if status, err := a.Manager.Status(ctx); err == nil {
		a.stdoutf("daemon: running pid=%d\n", status.PID)
	} else {
		healthy = false
		a.stdoutf("daemon: failed (%v)\n", err)
	}
	if err := daemon.ValidateSocketDirectory(a.Manager.SocketPath); err != nil {
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
	return (daemon.ProcessApproverLauncher{}).CheckHealth(ctx)
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
	client    *daemon.Client
	requestID string
	nonce     string
	stderr    io.Writer
}

func (r daemonAuditReporter) Record(ctx context.Context, event execwrap.AuditEvent) error {
	switch event.Type {
	case "command_starting":
		return nil
	case "command_started":
		if err := r.client.ReportStarted(ctx, r.requestID, r.nonce, event.ChildPID); err != nil {
			if isFatalCommandStartedAuditFailure(err) {
				return err
			}
			_, _ = fmt.Fprintf(
				r.stderr,
				"agent-secret: warning: daemon disconnected after child start; command_started audit was not recorded: %v\n",
				err,
			)
		}
	case "command_completed":
		if err := r.client.ReportCompleted(ctx, r.requestID, r.nonce, event.ExitCode, event.Signal); err != nil {
			_, _ = fmt.Fprintf(r.stderr, "agent-secret: warning: daemon completion audit was not recorded: %v\n", err)
		}
	}
	return nil
}

func isFatalCommandStartedAuditFailure(err error) bool {
	if errors.Is(err, daemon.ErrInvalidNonce) ||
		errors.Is(err, daemon.ErrMalformedEnvelope) ||
		errors.Is(err, daemon.ErrProtocolType) {
		return true
	}

	var protocolErr *daemon.ProtocolError
	if !errors.As(err, &protocolErr) {
		return false
	}
	switch protocolErr.Code {
	case "bad_command_started",
		"bad_envelope",
		"bad_type",
		"invalid_nonce",
		"request_active",
		"request_expired",
		"stale_approval",
		"untrusted_client":
		return true
	default:
		return false
	}
}

func (a App) randomID(prefix string) (string, error) {
	return randid.Generate(a.RandomReader, prefix)
}
