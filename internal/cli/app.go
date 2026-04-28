package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
)

type App struct {
	Parser  Parser
	Manager daemon.Manager
	Stdout  io.Writer
	Stderr  io.Writer
}

func NewApp(manager daemon.Manager, stdout io.Writer, stderr io.Writer) App {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	return App{
		Parser:  NewParser(time.Now),
		Manager: manager,
		Stdout:  stdout,
		Stderr:  stderr,
	}
}

func (a App) Run(ctx context.Context, args []string) int {
	command, err := a.Parser.Parse(args)
	if errors.Is(err, ErrHelpRequested) {
		fmt.Fprintln(a.Stdout, command.HelpText)
		return 0
	}
	if err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: %v\n", err)
		return 2
	}

	switch command.Kind {
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
	default:
		fmt.Fprintf(a.Stderr, "agent-secret: unsupported command %s\n", command.Kind)
		return 2
	}
}

func (a App) runExec(ctx context.Context, command Command) int {
	if err := a.Manager.EnsureRunning(ctx); err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: start daemon: %v\n", err)
		return 1
	}
	client, err := a.Manager.Connect(ctx)
	if err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: connect daemon: %v\n", err)
		return 1
	}
	defer client.Close()

	requestID := randomID("req")
	nonce := randomID("nonce")
	payload, err := client.RequestExec(ctx, requestID, nonce, command.ExecRequest)
	if err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: request rejected: %v\n", err)
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
		Path:          command.ExecRequest.ResolvedExecutable,
		Args:          command.ExecRequest.Command[1:],
		Dir:           command.ExecRequest.CWD,
		Env:           payload.Env,
		SecretAliases: payload.SecretAliases,
		OverrideEnv:   command.ExecRequest.OverrideEnv,
		Stdout:        a.Stdout,
		Stderr:        a.Stderr,
		Audit:         reporter,
	}, interrupts)
	if err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: %v\n", err)
		return 1
	}
	return result.ExitCode
}

func (a App) runDaemonStatus(ctx context.Context) int {
	status, err := a.Manager.Status(ctx)
	if err != nil {
		fmt.Fprintf(a.Stdout, "agent-secretd: stopped (%v)\n", err)
		return 1
	}
	fmt.Fprintf(a.Stdout, "agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStart(ctx context.Context) int {
	if err := a.Manager.Start(ctx); err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: start daemon: %v\n", err)
		return 1
	}
	status, err := a.Manager.Status(ctx)
	if err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: daemon started but status failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.Stdout, "agent-secretd: running pid=%d\n", status.PID)
	return 0
}

func (a App) runDaemonStop(ctx context.Context) int {
	if err := a.Manager.Stop(ctx); err != nil {
		fmt.Fprintf(a.Stderr, "agent-secret: stop daemon: %v\n", err)
		return 1
	}
	fmt.Fprintln(a.Stdout, "agent-secretd: stopped")
	return 0
}

func (a App) runDoctor(ctx context.Context) int {
	auditPath, auditErr := audit.DefaultPath()
	fmt.Fprintln(a.Stdout, "agent-secret doctor")
	fmt.Fprintf(a.Stdout, "platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(a.Stdout, "daemon socket: %s\n", a.Manager.SocketPath)
	if auditErr != nil {
		fmt.Fprintf(a.Stdout, "audit log: unavailable (%v)\n", auditErr)
	} else {
		fmt.Fprintf(a.Stdout, "audit log: %s\n", auditPath)
	}
	if status, err := a.Manager.Status(ctx); err == nil {
		fmt.Fprintf(a.Stdout, "daemon: running pid=%d\n", status.PID)
	} else {
		fmt.Fprintf(a.Stdout, "daemon: stopped (%v)\n", err)
	}
	return 0
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
			if isProtocolFailure(err) {
				return err
			}
			fmt.Fprintf(r.stderr, "agent-secret: warning: daemon disconnected after child start; command_started audit was not recorded: %v\n", err)
		}
	case "command_completed":
		if err := r.client.ReportCompleted(ctx, r.requestID, r.nonce, event.ExitCode, event.Signal); err != nil {
			fmt.Fprintf(r.stderr, "agent-secret: warning: daemon completion audit was not recorded: %v\n", err)
		}
	}
	return nil
}

func isProtocolFailure(err error) bool {
	var protocolErr *daemon.ProtocolError
	return errors.As(err, &protocolErr)
}

func randomID(prefix string) string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(fmt.Sprintf("generate random id: %v", err))
	}
	return prefix + "_" + hex.EncodeToString(data[:])
}
