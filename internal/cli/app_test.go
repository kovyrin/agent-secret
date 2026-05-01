package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/policy"
	"github.com/kovyrin/agent-secret/internal/request"
)

func TestAppExecRunsChildWithApprovedEnvAndPassthrough(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	ref := "op://Example/Item/token"
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{ref: "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	socketPath := client.SocketPath
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{SocketPath: socketPath}, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=" + ref,
		"--",
		os.Args[0], "-test.run=TestAppExecRunsChildWithApprovedEnvAndPassthrough", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
	}
}

func TestAppExecRunsChildWithEnvFileSecretsAndPlainEnv(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	ref := "op://Example/Item/token"
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{ref: "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	envFilePath := filepath.Join(t.TempDir(), ".env")
	envFile := "TOKEN=" + ref + "\nPLAIN_ENV=from-file\n"
	if err := os.WriteFile(envFilePath, []byte(envFile), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{SocketPath: client.SocketPath}, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")
	t.Setenv("AGENT_SECRET_APP_EXPECT_PLAIN", "from-file")
	t.Setenv("TOKEN", "parent-token")
	t.Setenv("PLAIN_ENV", "parent")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--env-file", envFilePath,
		"--",
		os.Args[0], "-test.run=TestAppExecRunsChildWithEnvFileSecretsAndPlainEnv", "--", "child",
	})
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "env-ok" {
		t.Fatalf("stdout = %q, want env-ok", stdout.String())
	}
}

func TestAppExecStopsBeforeSpawnOnApprovalDenial(t *testing.T) {
	if os.Getenv("AGENT_SECRET_APP_EXEC_HELPER") == "1" {
		runAppExecHelper()
		return
	}

	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: false}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{SocketPath: client.SocketPath}, &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecStopsBeforeSpawnOnApprovalDenial", "--", "child",
	})
	if code == 0 {
		t.Fatal("denied request unexpectedly succeeded")
	}
	if strings.Contains(stdout.String(), "env-ok") {
		t.Fatalf("child appears to have run after denial: stdout=%q", stdout.String())
	}
}

func TestAppDaemonStatusAndDoctor(t *testing.T) {
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{SocketPath: client.SocketPath}, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"daemon", "status"}); code != 0 {
		t.Fatalf("daemon status exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "running pid=") {
		t.Fatalf("daemon status output = %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"doctor"}); code != 0 {
		t.Fatalf("doctor exit=%d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "audit log:") || !strings.Contains(stdout.String(), "daemon socket:") {
		t.Fatalf("doctor output missing diagnostics: %q", stdout.String())
	}
}

func TestAppDaemonStartAndStopCommands(t *testing.T) {
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{SocketPath: client.SocketPath}, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"daemon", "start"}); code != 0 {
		t.Fatalf("daemon start exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "running pid=") {
		t.Fatalf("daemon start output = %q", stdout.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "stop"}); code != 0 {
		t.Fatalf("daemon stop exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	if strings.TrimSpace(stdout.String()) != "agent-secretd: stopped" {
		t.Fatalf("daemon stop output = %q", stdout.String())
	}
}

func TestAppReportsParseErrorsAndStoppedDaemonStatus(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{SocketPath: filepath.Join(t.TempDir(), "missing.sock")}, &stdout, &stderr)

	if code := app.Run(context.Background(), []string{"bananas"}); code != 2 {
		t.Fatalf("unknown command exit=%d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("parse error stderr = %q", stderr.String())
	}

	stderr.Reset()
	if code := app.Run(context.Background(), []string{"daemon", "status"}); code != 1 {
		t.Fatalf("stopped daemon status exit=%d, want 1", code)
	}
	if !strings.Contains(stdout.String(), "agent-secretd: stopped") {
		t.Fatalf("stopped daemon status stdout = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stopped daemon status wrote stderr: %q", stderr.String())
	}
}

func TestAppExecReportsDaemonStartFailureBeforeSpawn(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{
		SocketPath: filepath.Join(t.TempDir(), "missing.sock"),
	}, &stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=op://Example/Item/token",
		"--",
		os.Args[0], "-test.run=TestAppExecReportsDaemonStartFailureBeforeSpawn", "--", "child",
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "start daemon") {
		t.Fatalf("stderr = %q, want start daemon failure", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want no child output", stdout.String())
	}
}

func TestNewAppDefaultsWritersAndHelpRun(t *testing.T) {
	app := NewApp(daemon.Manager{}, nil, nil)
	if app.Stdout == nil || app.Stderr == nil {
		t.Fatalf("NewApp did not install default writers: %+v", app)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app.Stdout = &stdout
	app.Stderr = &stderr
	if code := app.Run(context.Background(), []string{"help"}); code != 0 {
		t.Fatalf("help exit = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "agent-secret controls") {
		t.Fatalf("help output = %q", stdout.String())
	}
}

func TestDaemonAuditReporterTreatsProtocolFailureAsFatal(t *testing.T) {
	protocolErr := &daemon.ProtocolError{Code: "invalid_nonce", Message: "bad nonce"}
	if !isProtocolFailure(protocolErr) {
		t.Fatal("protocol error was not classified as protocol failure")
	}
	if isProtocolFailure(errors.New("network closed")) {
		t.Fatal("plain error was classified as protocol failure")
	}
}

func runAppExecHelper() {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "child" {
		return
	}
	if os.Getenv("TOKEN") != "synthetic-secret-value" {
		fmt.Println("env-missing")
		os.Exit(42)
	}
	if expectedPlain := os.Getenv("AGENT_SECRET_APP_EXPECT_PLAIN"); expectedPlain != "" {
		if os.Getenv("PLAIN_ENV") != expectedPlain {
			fmt.Println("plain-env-missing")
			os.Exit(43)
		}
	}
	fmt.Println("env-ok")
	os.Exit(0)
}

type appTestClient struct {
	SocketPath string
}

type appApprover struct {
	decision daemon.ApprovalDecision
}

func (a *appApprover) ApproveExec(
	_ context.Context,
	_ string,
	_ string,
	_ request.ExecRequest,
) (daemon.ApprovalDecision, error) {
	return a.decision, nil
}

type appResolver struct {
	values map[string]string
}

func (r *appResolver) Resolve(_ context.Context, ref string, _ string) (string, error) {
	return r.values[ref], nil
}

type appAudit struct{}

func (a *appAudit) Record(_ context.Context, _ audit.Event) error {
	return nil
}

func (a *appAudit) ApprovalReused(_ context.Context, _ policy.ReuseAuditEvent) error {
	return nil
}

func (a *appAudit) Preflight(context.Context) error {
	return nil
}

type appAllowPeer struct{}

func (appAllowPeer) Validate(_ *net.UnixConn) error {
	return nil
}

func startAppTestServer(t *testing.T, opts daemon.BrokerOptions) (appTestClient, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-app-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := daemon.ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	broker, err := daemon.NewBroker(opts)
	if err != nil {
		t.Fatalf("NewBroker returned error: %v", err)
	}
	server, err := daemon.NewServer(daemon.ServerOptions{Broker: broker, Validator: appAllowPeer{}})
	if err != nil {
		t.Fatalf("NewServer returned error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	return appTestClient{SocketPath: path}, func() {
		cancel()
		_ = listener.Close()
		<-done
		_ = os.RemoveAll(dir)
	}
}
