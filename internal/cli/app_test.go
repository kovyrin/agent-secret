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
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/install"
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
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=" + ref,
		"--allow-mutable-executable",
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
	app := NewApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")
	t.Setenv("AGENT_SECRET_APP_EXPECT_PLAIN", "from-file")
	t.Setenv("TOKEN", "parent-token")
	t.Setenv("PLAIN_ENV", "parent")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--env-file", envFilePath,
		"--allow-mutable-executable",
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
	app := NewApp(appTestManager(client), &stdout, &stderr)
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=op://Example/Item/token",
		"--allow-mutable-executable",
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
	t.Setenv("HOME", t.TempDir())
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(appTestManager(client), &stdout, &stderr)
	app.DoctorApproverCheck = func(context.Context) error { return nil }
	app.DoctorOnePasswordCheck = func(context.Context) error { return nil }

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
	if !strings.Contains(stdout.String(), "audit log: writable") ||
		!strings.Contains(stdout.String(), "daemon startup: ok") ||
		!strings.Contains(stdout.String(), "socket directory: private") ||
		!strings.Contains(stdout.String(), "native approver: ok") ||
		!strings.Contains(stdout.String(), "1password desktop integration: ok") {
		t.Fatalf("doctor output missing diagnostics: %q", stdout.String())
	}
}

func TestAppDaemonStatusUsesDefaultProtocolDeadline(t *testing.T) {
	client, cleanup := startStallingAppDaemon(t)
	defer cleanup()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{
		SocketPath:      client.SocketPath,
		DaemonPath:      os.Args[0],
		ProtocolTimeout: 25 * time.Millisecond,
		StartupTimeout:  25 * time.Millisecond,
	}, &stdout, &stderr)

	done := make(chan int, 1)
	go func() {
		done <- app.Run(context.Background(), []string{"daemon", "status"})
	}()

	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("daemon status exit=%d, want stopped failure; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "agent-secretd: stopped") {
			t.Fatalf("daemon status stdout = %q", stdout.String())
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("daemon status did not return after default protocol deadline")
	}
}

func TestAppDoctorReportsFailureWithoutSecretValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{"op://Example/Item/token": "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(appTestManager(client), &stdout, &stderr)
	app.DoctorApproverCheck = func(context.Context) error { return nil }
	app.DoctorOnePasswordCheck = func(context.Context) error {
		return errors.New("desktop integration unavailable")
	}

	code := app.Run(context.Background(), []string{"doctor"})
	if code != 1 {
		t.Fatalf("doctor exit=%d, want 1; stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "1password desktop integration: failed") {
		t.Fatalf("doctor stdout = %q, want 1Password failure", stdout.String())
	}
	if strings.Contains(stdout.String(), "synthetic-secret-value") || strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("doctor leaked secret: stdout=%q stderr=%q", stdout.String(), stderr.String())
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
	app := NewApp(appTestManager(client), &stdout, &stderr)

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

func TestAppInstallCommands(t *testing.T) {
	t.Run("cli", func(t *testing.T) {
		var gotOptions install.CLIOptions
		runInstallCommandTest(t, []string{"install-cli", "--bin-dir", "/tmp/bin", "--force"}, func(app *App) {
			app.InstallCLI = func(options install.CLIOptions) (install.CLIResult, error) {
				gotOptions = options
				return install.CLIResult{
					LinkPath:   filepath.Join(options.BinDir, "agent-secret"),
					TargetPath: "/Applications/Agent Secret.app/Contents/Resources/bin/agent-secret",
				}, nil
			}
		}, "/tmp/bin/agent-secret")
		if gotOptions.BinDir != "/tmp/bin" || !gotOptions.Force {
			t.Fatalf("install-cli options = %+v", gotOptions)
		}
	})

	t.Run("skill", func(t *testing.T) {
		var gotOptions install.SkillOptions
		runInstallCommandTest(t, []string{"skill-install", "--skills-dir", "/tmp/skills", "--force"}, func(app *App) {
			app.InstallSkill = func(options install.SkillOptions) (install.SkillResult, error) {
				gotOptions = options
				return install.SkillResult{
					LinkPath:   filepath.Join(options.SkillsDir, "agent-secret"),
					TargetPath: "/Applications/Agent Secret.app/Contents/Resources/skills/agent-secret",
				}, nil
			}
		}, "/tmp/skills/agent-secret")
		if gotOptions.SkillsDir != "/tmp/skills" || !gotOptions.Force {
			t.Fatalf("skill-install options = %+v", gotOptions)
		}
	})
}

func runInstallCommandTest(t *testing.T, args []string, configure func(*App), stdoutWant string) {
	t.Helper()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(daemon.Manager{}, &stdout, &stderr)
	configure(&app)

	code := app.Run(context.Background(), args)
	if code != 0 {
		t.Fatalf("%v exit=%d stderr=%q stdout=%q", args, code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), stdoutWant) {
		t.Fatalf("%v stdout = %q, want %q", args, stdout.String(), stdoutWant)
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
		"--allow-mutable-executable",
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

func TestAppExecReportsRandomIDFailureBeforeRequest(t *testing.T) {
	ref := "op://Example/Item/token"
	client, cleanup := startAppTestServer(t, daemon.BrokerOptions{
		Approver: &appApprover{decision: daemon.ApprovalDecision{Approved: true}},
		Resolver: &appResolver{values: map[string]string{ref: "synthetic-secret-value"}},
		Audit:    &appAudit{},
	})
	defer cleanup()

	entropyErr := errors.New("entropy unavailable")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := NewApp(appTestManager(client), &stdout, &stderr)
	app.RandomReader = failingRandomReader{err: entropyErr}
	t.Setenv("AGENT_SECRET_APP_EXEC_HELPER", "1")

	code := app.Run(context.Background(), []string{
		"exec",
		"--reason", "Run helper",
		"--secret", "TOKEN=" + ref,
		"--allow-mutable-executable",
		"--",
		os.Args[0], "-test.run=TestAppExecReportsRandomIDFailureBeforeRequest", "--", "child",
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "generate request id") || !strings.Contains(stderr.String(), entropyErr.Error()) {
		t.Fatalf("stderr = %q, want random id failure", stderr.String())
	}
	if strings.Contains(stderr.String(), "synthetic-secret-value") {
		t.Fatalf("stderr leaked secret: %q", stderr.String())
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

func appTestManager(client appTestClient) daemon.Manager {
	return daemon.Manager{SocketPath: client.SocketPath, DaemonPath: os.Args[0]}
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

type failingRandomReader struct {
	err error
}

func (r failingRandomReader) Read(_ []byte) (int, error) {
	return 0, r.err
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
	server, err := daemon.NewServer(daemon.ServerOptions{
		Broker:        broker,
		Validator:     appAllowPeer{},
		ExecValidator: daemon.NewTrustedExecutableValidator(daemon.CurrentExecutableTrustedClientPaths()),
	})
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

func startStallingAppDaemon(t *testing.T) (appTestClient, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-app-stall-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := daemon.ListenUnix(path)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("ListenUnix returned error: %v", err)
	}

	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = fmt.Fscan(conn)
		<-release
		done <- nil
	}()

	return appTestClient{SocketPath: path}, func() {
		close(release)
		_ = listener.Close()
		defer func() { _ = os.RemoveAll(dir) }()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("stalling app daemon returned error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("stalling app daemon did not stop")
		}
	}
}
