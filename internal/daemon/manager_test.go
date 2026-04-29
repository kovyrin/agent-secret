package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
)

func TestManagerStartsDaemonAndStopsItExplicitly(t *testing.T) {
	if os.Getenv("AGENT_SECRET_DAEMON_MANAGER_HELPER") == "1" {
		runDaemonManagerHelper(t)
		return
	}

	dir, err := os.MkdirTemp("/tmp", "agent-secret-manager-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socketPath := filepath.Join(dir, "d.sock")
	manager := Manager{
		SocketPath:     socketPath,
		DaemonPath:     os.Args[0],
		DaemonArgs:     []string{"-test.run=TestManagerStartsDaemonAndStopsItExplicitly", "--", "--socket", "{socket}"},
		StartupTimeout: 2 * time.Second,
	}
	t.Setenv("AGENT_SECRET_DAEMON_MANAGER_HELPER", "1")

	if err := manager.EnsureRunning(context.Background()); err != nil {
		t.Fatalf("EnsureRunning returned error: %v", err)
	}
	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatalf("Status returned error: %v", err)
	}
	if status.PID <= 0 || status.PID == os.Getpid() {
		t.Fatalf("daemon pid = %d, want separate process", status.PID)
	}
	if err := manager.EnsureRunning(context.Background()); err != nil {
		t.Fatalf("second EnsureRunning returned error: %v", err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
	waitForStatusFailure(t, manager)
}

func runDaemonManagerHelper(t *testing.T) {
	t.Helper()
	socketPath := ""
	for i, arg := range os.Args {
		if arg == "--socket" && i+1 < len(os.Args) {
			socketPath = os.Args[i+1]
			break
		}
	}
	if socketPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "missing --socket")
		os.Exit(64)
	}
	aud := &memoryAudit{}
	broker, err := NewBroker(BrokerOptions{
		Approver: &mockApprover{decision: ApprovalDecision{Approved: true}},
		Resolver: &mockResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "new broker: %v\n", err)
		os.Exit(70)
	}
	server, err := NewServer(ServerOptions{Broker: broker, Validator: allowPeerValidator{}})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "new server: %v\n", err)
		os.Exit(70)
	}
	if err := server.ListenAndServe(context.Background(), socketPath); err != nil {
		if len(aud.Events()) > 0 && aud.Events()[len(aud.Events())-1].Type == audit.EventDaemonStop {
			os.Exit(0)
		}
		_, _ = fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(70)
	}
	os.Exit(0)
}

func waitForStatusFailure(t *testing.T, manager Manager) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := manager.Status(context.Background()); err != nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("daemon still responded after stop")
}

func TestNewManagerUsesDefaultSocketAndDaemonPathOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_SECRET_DAEMON_PATH", "/tmp/agent-secretd-test")

	manager, err := NewManager("")
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	wantSocket := filepath.Join(home, "Library", "Application Support", "agent-secret", "agent-secretd.sock")
	if manager.SocketPath != wantSocket {
		t.Fatalf("SocketPath = %q, want %q", manager.SocketPath, wantSocket)
	}
	if manager.DaemonPath != "/tmp/agent-secretd-test" {
		t.Fatalf("DaemonPath = %q, want env override", manager.DaemonPath)
	}
	if manager.StartupTimeout != 3*time.Second {
		t.Fatalf("StartupTimeout = %s, want 3s", manager.StartupTimeout)
	}
}

func TestManagerDaemonArgsReplaceSocketPlaceholder(t *testing.T) {
	t.Parallel()

	manager := Manager{SocketPath: "/tmp/agent-secret.sock"}
	if got := manager.daemonArgs(); !slices.Equal(got, []string{"--socket", "/tmp/agent-secret.sock"}) {
		t.Fatalf("default daemon args = %v", got)
	}

	manager.DaemonArgs = []string{"--listen", "{socket}", "--verbose"}
	got := manager.daemonArgs()
	want := []string{"--listen", "/tmp/agent-secret.sock", "--verbose"}
	if !slices.Equal(got, want) {
		t.Fatalf("custom daemon args = %v, want %v", got, want)
	}
}

func TestDaemonAppPathAndStartCommand(t *testing.T) {
	t.Setenv("AGENT_SECRET_DAEMON_APP_PATH", "/tmp/AgentSecretDaemon.app")
	t.Setenv("OP_ACCOUNT", "DefaultFixture")
	t.Setenv("AGENT_SECRET_1PASSWORD_ACCOUNT", "Fixture")
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/Applications/AgentSecretApprover.app")

	appPath, ok := defaultDaemonAppPath()
	if runtime.GOOS == "darwin" {
		if !ok || appPath != "/tmp/AgentSecretDaemon.app" {
			t.Fatalf("default daemon app path = %q, %v", appPath, ok)
		}
		cmd := daemonStartCommand(context.Background(), appPath, []string{"--socket", "/tmp/d.sock"})
		if cmd.Path != "/usr/bin/open" {
			t.Fatalf("darwin app command path = %q, want /usr/bin/open", cmd.Path)
		}
		for _, want := range []string{
			"-g",
			"-n",
			appPath,
			"--env",
			"OP_ACCOUNT=DefaultFixture",
			"--env",
			"AGENT_SECRET_1PASSWORD_ACCOUNT=Fixture",
			"AGENT_SECRET_APPROVER_PATH=/Applications/AgentSecretApprover.app",
			"--args",
			"--socket",
			"/tmp/d.sock",
		} {
			if !slices.Contains(cmd.Args, want) {
				t.Fatalf("darwin app command args %v missing %q", cmd.Args, want)
			}
		}
		return
	}

	if ok || appPath != "" {
		t.Fatalf("non-darwin daemon app path = %q, %v", appPath, ok)
	}
	cmd := daemonStartCommand(context.Background(), "/tmp/agent-secretd", []string{"--socket", "/tmp/d.sock"})
	if cmd.Path != "/tmp/agent-secretd" {
		t.Fatalf("daemon command path = %q, want direct binary", cmd.Path)
	}
}
