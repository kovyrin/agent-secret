package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/audit"
	"github.com/kovyrin/agent-secret/internal/daemon"
	"github.com/kovyrin/agent-secret/internal/daemon/approval"
	daemonbroker "github.com/kovyrin/agent-secret/internal/daemon/broker"
	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	daemonprocess "github.com/kovyrin/agent-secret/internal/daemon/process"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/itemmetadata"
	"github.com/kovyrin/agent-secret/internal/peercred"
	"github.com/kovyrin/agent-secret/internal/request"
	"github.com/kovyrin/agent-secret/internal/testsupport/testfs"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

const managerHelperBindUnavailablePrefix = "AGENT_SECRET_DAEMON_MANAGER_HELPER_BIND_UNAVAILABLE:"

type allowPeerValidator struct{}

func (allowPeerValidator) Info(conn *net.UnixConn) (peercred.Info, error) {
	return peercred.Inspect(conn)
}

func (allowPeerValidator) Validate(_ *net.UnixConn) error {
	return nil
}

type managerApprover struct{}

func (managerApprover) Approve(
	_ context.Context,
	_ approval.ApprovalRequestPayload,
) (approval.Decision, error) {
	return approval.Decision{Approved: true}, nil
}

type managerResolver struct {
	values map[string]string
}

func (r managerResolver) Resolve(_ context.Context, secret request.Secret) (string, error) {
	return r.values[resolverCallKey(secret.Ref.Raw, secret.Account)], nil
}

func (r managerResolver) DescribeItem(
	_ context.Context,
	ref itemmetadata.Ref,
	account string,
) (itemmetadata.Metadata, error) {
	return itemmetadata.Metadata{
		Account: account,
		Vault:   ref.Vault,
		Item:    ref.Item,
		Fields: []itemmetadata.Field{
			{
				Label:     "token",
				Type:      "Concealed",
				Concealed: true,
				Ref:       itemmetadata.BuildFieldRef(ref.Vault, ref.Item, "", "token"),
				Alias:     "TOKEN",
			},
		},
	}, nil
}

type managerAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *managerAudit) Record(_ context.Context, event audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *managerAudit) Preflight(context.Context) error {
	return nil
}

func (m *managerAudit) Events() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.events)
}

func resolverCallKey(ref string, account string) string {
	if account == "" {
		return ref
	}
	return ref + "\x00" + account
}

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
	output, err := os.Create(filepath.Join(dir, "daemon-helper.log")) //nolint:gosec // G304: manager helper log is inside a test-owned temp directory.
	if err != nil {
		t.Fatalf("create helper output log: %v", err)
	}
	defer func() { _ = output.Close() }()
	manager := Manager{
		socketPath:     socketPath,
		DaemonPath:     os.Args[0],
		DaemonArgs:     []string{"-test.run=TestManagerStartsDaemonAndStopsItExplicitly", "--", "--socket", "{socket}"},
		StartupTimeout: 2 * time.Second,
		daemonStdout:   output,
		daemonStderr:   output,
	}
	t.Setenv("AGENT_SECRET_DAEMON_MANAGER_HELPER", "1")

	if err := manager.EnsureRunning(context.Background()); err != nil {
		helperOutput := readManagerHelperOutput(t, output.Name())
		if strings.Contains(helperOutput, managerHelperBindUnavailablePrefix) {
			t.Skipf("Unix socket bind unavailable in daemon helper: %s", helperOutput)
		}
		t.Fatalf("EnsureRunning returned error: %v\nhelper output:\n%s", err, helperOutput)
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
	if _, err := manager.Status(context.Background()); err == nil {
		t.Fatal("daemon still responded after stop")
	}
}

func readManagerHelperOutput(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: helper output path is created by this test.
	if err != nil {
		return fmt.Sprintf("read %s: %v", path, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return "(empty)"
	}
	return string(data)
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
	aud := &managerAudit{}
	broker, err := daemonbroker.New(daemonbroker.Options{
		Approver: managerApprover{},
		Resolver: managerResolver{values: map[string]string{"op://Example/Item/token": "value"}},
		Audit:    aud,
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "new broker: %v\n", err)
		os.Exit(70)
	}
	server, err := daemon.NewServer(daemon.ServerOptions{
		Broker:          broker,
		Validator:       allowPeerValidator{},
		ClientValidator: peertrust.NewExecutableValidator(currentExecutableClientPaths(t)),
	})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "new server: %v\n", err)
		os.Exit(70)
	}
	if err := server.ListenAndServe(context.Background(), socketPath); err != nil {
		if len(aud.Events()) > 0 && aud.Events()[len(aud.Events())-1].Type == audit.EventDaemonStop {
			os.Exit(0)
		}
		if unixsocket.IsBindUnavailable(err) {
			_, _ = fmt.Fprintf(os.Stderr, "%s %v\n", managerHelperBindUnavailablePrefix, err)
			os.Exit(75)
		}
		_, _ = fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(70)
	}
	os.Exit(0)
}

func TestManagerStatusUnavailableAcceptsOnlyUnavailableDaemon(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}

	unavailable, err := manager.statusUnavailable(context.Background())
	if err != nil {
		t.Fatalf("statusUnavailable returned error: %v", err)
	}
	if !unavailable {
		t.Fatal("statusUnavailable = false, want true for missing daemon socket")
	}
}

func currentExecutableClientPaths(t *testing.T) []string {
	t.Helper()
	paths, err := peertrust.CurrentExecutableClientPaths()
	if err != nil {
		t.Fatalf("CurrentExecutableClientPaths returned error: %v", err)
	}
	return paths
}

func TestManagerControlMethodsReportMissingDaemon(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}

	if _, err := manager.Status(context.Background()); !errors.Is(err, socket.ErrDaemonUnavailable) {
		t.Fatalf("Status error = %v, want daemon unavailable", err)
	}
	if err := manager.CheckOnePassword(context.Background(), "my.1password.ca"); !errors.Is(err, socket.ErrDaemonUnavailable) {
		t.Fatalf("CheckOnePassword error = %v, want daemon unavailable", err)
	}
	if err := manager.Stop(context.Background()); !errors.Is(err, socket.ErrDaemonUnavailable) {
		t.Fatalf("Stop error = %v, want daemon unavailable", err)
	}
}

func TestManagerWaitUntilReadyPreservesStartupDeadline(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	err := manager.waitUntilReady(ctx, time.Hour)
	if !errors.Is(err, socket.ErrDaemonUnavailable) {
		t.Fatalf("waitUntilReady error = %v, want daemon unavailable", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitUntilReady error = %v, want context deadline exceeded", err)
	}
}

func TestManagerWaitUntilUnavailableReturnsForMissingSocket(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}

	if err := manager.waitUntilUnavailable(context.Background(), 0); err != nil {
		t.Fatalf("waitUntilUnavailable returned error: %v", err)
	}
}

func TestManagerStartRequiresDaemonPathAfterSocketPreparation(t *testing.T) {
	t.Parallel()

	dir := testfs.ShortTempDir(t, "agent-secret-manager-")
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: manager socket test needs a private custom directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	manager := Manager{
		socketPath:     filepath.Join(dir, "agent-secretd.sock"),
		StartupTimeout: time.Millisecond,
	}

	err := manager.EnsureRunning(context.Background())
	if err == nil || !strings.Contains(err.Error(), "daemon path is required") {
		t.Fatalf("EnsureRunning error = %v, want daemon path required", err)
	}
	if got := testfs.StatMode(t, dir); got != 0o700 {
		t.Fatalf("socket dir mode = %s, want 0700", got)
	}
}

func TestManagerStatusUnavailableReturnsOtherStatusErrors(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	manager := Manager{
		socketPath: path,
		DaemonPath: writeDaemonExecutableAt(t, t.TempDir()),
	}

	unavailable, err := manager.statusUnavailable(context.Background())
	if unavailable {
		t.Fatal("statusUnavailable = true for untrusted daemon peer")
	}
	if !errors.Is(err, peertrust.ErrUntrustedDaemon) {
		t.Fatalf("statusUnavailable error = %v, want %v", err, peertrust.ErrUntrustedDaemon)
	}
}

func TestManagerStatusUnavailableTreatsRetiringDaemonAsStillRunning(t *testing.T) {
	t.Parallel()

	path, stop := startFakeStatusErrorDaemon(t, protocol.ErrorCodeDaemonStopped)
	defer stop()
	manager := Manager{
		socketPath: path,
		DaemonPath: os.Args[0],
	}

	unavailable, err := manager.statusUnavailable(context.Background())
	if err != nil {
		t.Fatalf("statusUnavailable returned error: %v", err)
	}
	if unavailable {
		t.Fatal("statusUnavailable = true for retiring daemon, want false until socket disappears")
	}
}

func TestManagerStatusRejectsUntrustedDaemonPeer(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	manager := Manager{
		socketPath: path,
		DaemonPath: writeDaemonExecutableAt(t, t.TempDir()),
	}

	_, err := manager.Status(context.Background())
	if !errors.Is(err, peertrust.ErrUntrustedDaemon) {
		t.Fatalf("Status error = %v, want %v", err, peertrust.ErrUntrustedDaemon)
	}
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
	if manager.SocketPath() != wantSocket {
		t.Fatalf("SocketPath = %q, want %q", manager.SocketPath(), wantSocket)
	}
	if manager.DaemonPath == "/tmp/agent-secretd-test" {
		t.Fatalf("DaemonPath honored requester-controlled env override: %q", manager.DaemonPath)
	}
	if manager.StartupTimeout != 3*time.Second {
		t.Fatalf("StartupTimeout = %s, want 3s", manager.StartupTimeout)
	}
}

func TestNewManagerUsesExplicitSocketPath(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "custom.sock")
	manager, err := NewManager(socketPath)
	if err != nil {
		t.Fatalf("NewManager returned error: %v", err)
	}
	if manager.SocketPath() != socketPath {
		t.Fatalf("SocketPath = %q, want %q", manager.SocketPath(), socketPath)
	}
	if manager.DaemonPath == "" {
		t.Fatal("DaemonPath is empty")
	}
}

func TestManagerDaemonArgsReplaceSocketPlaceholder(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: "/tmp/agent-secret.sock"}
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

func TestManagerWriterPrefersConfiguredWriter(t *testing.T) {
	t.Parallel()

	fallback := &strings.Builder{}
	configured := &strings.Builder{}
	if got := managerWriter(fallback, configured); got != configured {
		t.Fatalf("managerWriter returned %T, want configured writer", got)
	}
}

func TestManagerProtocolTimeoutDefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	if got := (Manager{}).protocolTimeout(); got != DefaultClientProtocolTimeout {
		t.Fatalf("default protocol timeout = %s, want %s", got, DefaultClientProtocolTimeout)
	}
	manager := Manager{ProtocolTimeout: 250 * time.Millisecond}
	if got := manager.protocolTimeout(); got != 250*time.Millisecond {
		t.Fatalf("custom protocol timeout = %s, want 250ms", got)
	}
}

func TestManagerRejectsPermissiveCustomSocketParentWithoutChmod(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: this test intentionally creates a permissive custom socket directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	manager := Manager{
		socketPath:     filepath.Join(dir, "agent-secretd.sock"),
		DaemonPath:     filepath.Join(t.TempDir(), "missing-agent-secretd"),
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if !errors.Is(err, socket.ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if got := testfs.StatMode(t, dir); got != 0o755 {
		t.Fatalf("manager changed custom socket dir mode to %s", got)
	}
}

func TestManagerRejectsSymlinkedCustomSocketAncestorBeforeMkdirAll(t *testing.T) {
	t.Parallel()

	target := testfs.ShortTempDir(t, "agent-secret-manager-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: manager socket target is private in this test.
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(testfs.ShortTempDir(t, "agent-secret-manager-parent-"), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink socket ancestor: %v", err)
	}
	manager := Manager{
		socketPath:     filepath.Join(link, "nested", "agent-secretd.sock"),
		DaemonPath:     filepath.Join(t.TempDir(), "missing-agent-secretd"),
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if !errors.Is(err, socket.ErrInsecureSocketDirectory) {
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
		socketPath:     path,
		DaemonPath:     writeDaemonExecutableAt(t, t.TempDir()),
		StartupTimeout: time.Millisecond,
	}

	err := manager.Start(context.Background())
	if !errors.Is(err, peertrust.ErrUntrustedDaemon) {
		t.Fatalf("Start error = %v, want %v", err, peertrust.ErrUntrustedDaemon)
	}
}

func TestManagerStartPropagatesStaleSocketCleanupError(t *testing.T) {
	t.Parallel()

	dir := testfs.ShortTempDir(t, "agent-secret-manager-")
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: manager socket test needs a private custom directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	path := filepath.Join(dir, "agent-secretd.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fake socket path: %v", err)
	}
	manager := Manager{
		socketPath:     path,
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
	t.Setenv("AGENT_SECRET_APPROVER_PATH", "/tmp/PoisonApprover.app")

	appPath, ok := daemonprocess.DefaultDaemonAppPath()
	if runtime.GOOS != "darwin" {
		if ok || appPath != "" {
			t.Fatalf("non-darwin daemon app path = %q, %v", appPath, ok)
		}
		cmd := daemonprocess.StartCommand(context.Background(), "/tmp/agent-secretd", []string{"--socket", "/tmp/d.sock"})
		if cmd.Path != "/tmp/agent-secretd" {
			t.Fatalf("daemon command path = %q, want direct binary", cmd.Path)
		}
		return
	}
	if !ok || appPath != daemonAppPath {
		t.Fatalf("default daemon app path = %q, %v", appPath, ok)
	}
	cmd := daemonprocess.StartCommand(context.Background(), appPath, []string{"--socket", "/tmp/d.sock"})
	if cmd.Path != "/usr/bin/open" {
		t.Fatalf("darwin app command path = %q, want /usr/bin/open", cmd.Path)
	}
	for _, want := range []string{
		"-g",
		"-n",
		appPath,
		"--args",
		daemonprocess.AppLaunchSubcommand,
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
	if slices.Contains(cmd.Args, "--env") {
		t.Fatalf("darwin app command args forwarded environment: %v", cmd.Args)
	}
}

func startFakeExecDaemon(t *testing.T) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-fake-daemon-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		serveFakeExecPayload(conn)
	}()
	return path, func() {
		_ = listener.Close()
		<-done
		_ = os.RemoveAll(dir)
	}
}

func startFakeStatusErrorDaemon(t *testing.T, code protocol.ErrorCode) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-fake-status-daemon-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	path := filepath.Join(dir, "d.sock")
	listener, err := socket.ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		serveFakeStatusError(conn, code)
	}()
	return path, func() {
		_ = listener.Close()
		<-done
		_ = os.RemoveAll(dir)
	}
}

func serveFakeStatusError(conn *net.UnixConn, code protocol.ErrorCode) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var env protocol.Envelope
	if err := decoder.Decode(&env); err != nil {
		return
	}
	resp, err := protocol.NewEnvelope(protocol.TypeError, env.Correlation(), protocol.ErrorPayload{
		Code:    code,
		Message: "daemon stopped",
	})
	if err != nil {
		return
	}
	if err := encoder.Encode(resp); err != nil {
		return
	}
}

func serveFakeExecPayload(conn *net.UnixConn) {
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	var env protocol.Envelope
	if err := decoder.Decode(&env); err != nil {
		return
	}
	resp, err := protocol.NewEnvelope(protocol.TypeOK, env.Correlation(), protocol.ExecResponsePayload{
		Env:           map[string]string{"TOKEN": "attacker-controlled"},
		SecretAliases: []string{"TOKEN"},
	})
	if err != nil {
		return
	}
	if err := encoder.Encode(resp); err != nil {
		return
	}
}

func writeDaemonExecutableAt(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "agent-secretd")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon control tests need runnable fixture executables.
		t.Fatalf("write executable: %v", err)
	}
	return path
}
