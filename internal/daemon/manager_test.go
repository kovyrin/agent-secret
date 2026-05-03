package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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
	server, err := NewServer(ServerOptions{
		Broker:        broker,
		Validator:     allowPeerValidator{},
		ExecValidator: NewTrustedExecutableValidator(CurrentExecutableTrustedClientPaths()),
	})
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

func TestNewManagerIgnoresDaemonPathEnvironmentOverride(t *testing.T) {
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
	if manager.DaemonPath == "/tmp/agent-secretd-test" {
		t.Fatalf("DaemonPath honored requester-controlled env override: %q", manager.DaemonPath)
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

func TestManagerRejectsPermissiveCustomSocketParentWithoutChmod(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: this test intentionally creates a permissive custom socket directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	manager := Manager{
		SocketPath:     filepath.Join(dir, "agent-secretd.sock"),
		DaemonPath:     filepath.Join(t.TempDir(), "missing-agent-secretd"),
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if got := statMode(t, dir); got != 0o755 {
		t.Fatalf("manager changed custom socket dir mode to %s", got)
	}
}

func TestManagerRejectsSymlinkedCustomSocketAncestorBeforeMkdirAll(t *testing.T) {
	t.Parallel()

	target := shortTempDir(t, "agent-secret-manager-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: manager socket target is private in this test.
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(shortTempDir(t, "agent-secret-manager-parent-"), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink socket ancestor: %v", err)
	}
	manager := Manager{
		SocketPath:     filepath.Join(link, "nested", "agent-secretd.sock"),
		DaemonPath:     filepath.Join(t.TempDir(), "missing-agent-secretd"),
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manager followed symlinked socket ancestor: %v", err)
	}
}

func TestManagerStartRejectsUntrustedLiveSocket(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	manager := Manager{
		SocketPath:     path,
		DaemonPath:     writeExecutableAt(t, t.TempDir(), "agent-secretd"),
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if !errors.Is(err, ErrUntrustedDaemon) {
		t.Fatalf("Start error = %v, want %v", err, ErrUntrustedDaemon)
	}
}

func TestManagerStartPropagatesStaleSocketCleanupError(t *testing.T) {
	t.Parallel()

	dir := shortTempDir(t, "agent-secret-manager-")
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: manager socket test needs a private custom directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	path := filepath.Join(dir, "agent-secretd.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fake socket path: %v", err)
	}
	manager := Manager{
		SocketPath:     path,
		DaemonPath:     os.Args[0],
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "refusing to remove non-socket path") {
		t.Fatalf("Start error = %v, want stale socket cleanup failure", err)
	}
}

func TestDaemonAppPathAndStartCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	daemonAppPath := filepath.Join(
		home,
		"Applications",
		"Agent Secret.app",
		"Contents",
		"Library",
		"Helpers",
		"AgentSecretDaemon.app",
	)
	if err := os.MkdirAll(daemonAppPath, 0o750); err != nil {
		t.Fatalf("mkdir daemon app: %v", err)
	}
	t.Setenv("AGENT_SECRET_DAEMON_APP_PATH", "/tmp/PoisonDaemon.app")
	t.Setenv("OP_ACCOUNT", "DefaultFixture")
	t.Setenv("AGENT_SECRET_1PASSWORD_ACCOUNT", "Fixture")
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/PoisonApprover.app")

	appPath, ok := defaultDaemonAppPath()
	if runtime.GOOS == "darwin" {
		if !ok || appPath != daemonAppPath {
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
			"--args",
			"--socket",
			"/tmp/d.sock",
		} {
			if !slices.Contains(cmd.Args, want) {
				t.Fatalf("darwin app command args %v missing %q", cmd.Args, want)
			}
		}
		if slices.Contains(cmd.Args, "AGENT_SECRET_APPROVER_PATH=/tmp/PoisonApprover.app") {
			t.Fatalf("darwin app command args forwarded poisoned approver path: %v", cmd.Args)
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

func TestDaemonAppPathForBundledExecutable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	appPath := filepath.Join(root, "Agent Secret.app")
	cliPath := filepath.Join(appPath, "Contents", "Resources", "bin", "agent-secret")
	daemonAppPath := filepath.Join(appPath, "Contents", "Library", "Helpers", "AgentSecretDaemon.app")
	if err := os.MkdirAll(filepath.Dir(cliPath), 0o750); err != nil {
		t.Fatalf("create cli dir: %v", err)
	}
	if err := os.MkdirAll(daemonAppPath, 0o750); err != nil {
		t.Fatalf("create daemon app: %v", err)
	}
	if err := os.WriteFile(cliPath, []byte("test"), 0o755); err != nil { //nolint:gosec // G306: bundled daemon path tests need a runnable CLI fixture.
		t.Fatalf("write cli: %v", err)
	}

	got, ok := daemonAppPathForExecutable(cliPath)
	if !ok || got != daemonAppPath {
		t.Fatalf("daemon app path = %q, %v, want %q, true", got, ok, daemonAppPath)
	}

	symlinkPath := filepath.Join(root, "bin", "agent-secret")
	if err := os.MkdirAll(filepath.Dir(symlinkPath), 0o750); err != nil {
		t.Fatalf("create symlink dir: %v", err)
	}
	if err := os.Symlink(cliPath, symlinkPath); err != nil {
		t.Fatalf("create cli symlink: %v", err)
	}
	resolvedDaemonAppPath, err := filepath.EvalSymlinks(daemonAppPath)
	if err != nil {
		t.Fatalf("resolve daemon app path: %v", err)
	}
	got, ok = daemonAppPathForExecutable(symlinkPath)
	if !ok || got != resolvedDaemonAppPath {
		t.Fatalf("daemon app path through symlink = %q, %v, want %q, true", got, ok, resolvedDaemonAppPath)
	}
}
