package cli

import (
	"bytes"
	"context"
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

func runAppExecHelper() {
	if len(os.Args) == 0 || os.Args[len(os.Args)-1] != "child" {
		return
	}
	if os.Getenv("TOKEN") != "synthetic-secret-value" {
		fmt.Println("env-missing")
		os.Exit(42)
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

func (r *appResolver) Resolve(_ context.Context, ref string) (string, error) {
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
