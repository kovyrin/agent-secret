package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
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
	"github.com/kovyrin/agent-secret/internal/helperidentity"
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

func TestUnavailableDaemonStatusErrorAcceptsClosedConnectionRace(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		fmt.Errorf("send daemon message %s: %w", protocol.TypeDaemonStatus, syscall.EPIPE),
		fmt.Errorf("read daemon response %s: %w", protocol.TypeDaemonStatus, syscall.ECONNRESET),
		io.EOF,
		socket.ErrDaemonUnavailable,
	} {
		if !isUnavailableDaemonStatusError(err) {
			t.Fatalf("isUnavailableDaemonStatusError(%v) = false, want true", err)
		}
	}
	if isUnavailableDaemonStatusError(errors.New("permission denied")) {
		t.Fatal("permission error was classified as daemon unavailable")
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

func TestManagerRepairReportsRunningCurrentHelper(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	hello := helperidentity.ForExecutable(executable, os.Getpid())
	path, stop := startFakeHelperDaemon(t, hello)
	defer stop()
	manager := Manager{
		socketPath: path,
		DaemonPath: executable,
	}

	result, err := manager.Repair(context.Background())
	if err != nil {
		t.Fatalf("Repair returned error: %v", err)
	}
	if result.Status != RepairStatusOK || result.PID != os.Getpid() {
		t.Fatalf("Repair result = %+v, want ok for current pid", result)
	}
	if !samePath(result.Hello.Executable, executable) {
		t.Fatalf("Repair hello executable = %q, want %q", result.Hello.Executable, executable)
	}
}

func TestManagerRepairRefreshesMismatchedTrustedHelper(t *testing.T) {
	if os.Getenv("AGENT_SECRET_DAEMON_MANAGER_REPAIR_HELPER") == "1" {
		runDaemonManagerHelper(t)
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	staleHello := helperidentity.ForExecutable(executable, os.Getpid())
	staleHello.BuildID += "-stale"
	path, stopStale := startFakeHelperDaemon(t, staleHello)
	defer stopStale()

	output, err := os.Create(filepath.Join(t.TempDir(), "repair-helper.log"))
	if err != nil {
		t.Fatalf("create helper output log: %v", err)
	}
	defer func() { _ = output.Close() }()
	manager := Manager{
		socketPath:     path,
		DaemonPath:     executable,
		DaemonArgs:     []string{"-test.run=TestManagerRepairRefreshesMismatchedTrustedHelper", "--", "--socket", "{socket}"},
		StartupTimeout: 2 * time.Second,
		daemonStdout:   output,
		daemonStderr:   output,
	}
	t.Setenv("AGENT_SECRET_DAEMON_MANAGER_REPAIR_HELPER", "1")

	result, err := manager.Repair(context.Background())
	if err != nil {
		helperOutput := readManagerHelperOutput(t, output.Name())
		if strings.Contains(helperOutput, managerHelperBindUnavailablePrefix) {
			t.Skipf("Unix socket bind unavailable in daemon repair helper: %s", helperOutput)
		}
		t.Fatalf("Repair returned error: %v\nhelper output:\n%s", err, helperOutput)
	}
	defer func() { _ = manager.Stop(context.Background()) }()
	if result.Status != RepairStatusRefreshed {
		t.Fatalf("Repair status = %q, want refreshed", result.Status)
	}
	if result.PID <= 0 || result.PID == os.Getpid() {
		t.Fatalf("Repair pid = %d, want fresh helper process", result.PID)
	}
	if result.Hello.BuildID != helperidentity.ForExecutable(executable, os.Getpid()).BuildID {
		t.Fatalf("Repair hello build id = %q, want current build id", result.Hello.BuildID)
	}
}

func TestManagerRepairSignalsTrustedHelperWhenStopRejectsClient(t *testing.T) {
	if os.Getenv("AGENT_SECRET_DAEMON_MANAGER_REPAIR_SIGNAL_HELPER") == "1" {
		runDaemonManagerHelper(t)
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	staleHello := helperidentity.ForExecutable(executable, os.Getpid())
	staleHello.BuildID += "-stale"
	path, stopStale := startFakeHelperDaemonWithOptions(t, fakeHelperOptions{
		hello:         staleHello,
		stopErrorCode: protocol.ErrorCodeUntrustedClient,
	})
	defer stopStale()

	output, err := os.Create(filepath.Join(t.TempDir(), "repair-helper.log"))
	if err != nil {
		t.Fatalf("create helper output log: %v", err)
	}
	defer func() { _ = output.Close() }()
	signalCalls := 0
	manager := Manager{
		socketPath:     path,
		DaemonPath:     executable,
		DaemonArgs:     []string{"-test.run=TestManagerRepairSignalsTrustedHelperWhenStopRejectsClient", "--", "--socket", "{socket}"},
		StartupTimeout: 2 * time.Second,
		daemonStdout:   output,
		daemonStderr:   output,
		signalProcess: func(pid int, sig os.Signal) error {
			signalCalls++
			if pid != os.Getpid() {
				t.Fatalf("signal pid = %d, want current fake helper process pid %d", pid, os.Getpid())
			}
			if sig != syscall.SIGTERM {
				t.Fatalf("signal = %v, want SIGTERM", sig)
			}
			stopStale()
			return nil
		},
	}
	t.Setenv("AGENT_SECRET_DAEMON_MANAGER_REPAIR_SIGNAL_HELPER", "1")

	result, err := manager.Repair(context.Background())
	if err != nil {
		helperOutput := readManagerHelperOutput(t, output.Name())
		if strings.Contains(helperOutput, managerHelperBindUnavailablePrefix) {
			t.Skipf("Unix socket bind unavailable in daemon repair helper: %s", helperOutput)
		}
		t.Fatalf("Repair returned error: %v\nhelper output:\n%s", err, helperOutput)
	}
	defer func() { _ = manager.Stop(context.Background()) }()
	if result.Status != RepairStatusRefreshed {
		t.Fatalf("Repair status = %q, want refreshed", result.Status)
	}
	if signalCalls != 1 {
		t.Fatalf("signal calls = %d, want 1", signalCalls)
	}
	if result.Hello.BuildID != helperidentity.ForExecutable(executable, os.Getpid()).BuildID {
		t.Fatalf("Repair hello build id = %q, want current build id", result.Hello.BuildID)
	}
}

func TestManagerRepairErrorClassifiers(t *testing.T) {
	t.Parallel()

	if peerProcessGoneError(nil) {
		t.Fatal("peerProcessGoneError(nil) = true, want false")
	}
	if !peerProcessGoneError(fmt.Errorf("inspect peer: %w", syscall.ESRCH)) {
		t.Fatal("peerProcessGoneError did not detect wrapped ESRCH")
	}
	if !peerProcessGoneError(errors.New("inspect daemon peer: proc_pidpath: no such process")) {
		t.Fatal("peerProcessGoneError did not detect proc_pidpath text")
	}
	if !helperUnavailableError(fmt.Errorf("%w: dial failed", socket.ErrDaemonUnavailable)) {
		t.Fatal("helperUnavailableError did not detect socket unavailable")
	}
	peerGoneUnavailable := fmt.Errorf(
		"%w: untrusted daemon peer: inspect daemon peer: proc_pidpath: no such process",
		socket.ErrDaemonUnavailable,
	)
	if !helperUnavailableError(peerGoneUnavailable) {
		t.Fatal("helperUnavailableError did not detect peer-gone unavailable error")
	}
	peerGoneUnexpected := errors.New("unexpected helper: proc_pidpath: no such process")
	if helperUnavailableError(peerGoneUnexpected) {
		t.Fatal("helperUnavailableError accepted peer-gone error without daemon unavailable")
	}
	classified := classifyHelperConnectError(errors.New("inspect daemon peer: proc_pidpath: no such process"))
	if !helperUnavailableError(classified) {
		t.Fatalf("classifyHelperConnectError = %v, want helper unavailable", classified)
	}
	unexpected := classifyHelperConnectError(peertrust.ErrUntrustedDaemon)
	if !errors.Is(unexpected, ErrUnexpectedHelper) {
		t.Fatalf("classifyHelperConnectError = %v, want ErrUnexpectedHelper", unexpected)
	}
}

func TestManagerTrustedHelperVanishedAfterTrustErrorRequiresUnavailableSocket(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}
	err := fmt.Errorf("%w: %w", ErrUnexpectedHelper, socket.ErrDaemonUnavailable)
	if !manager.trustedHelperVanishedAfterTrustError(context.Background(), err) {
		t.Fatal("trustedHelperVanishedAfterTrustError = false, want true for missing socket")
	}
	if manager.trustedHelperVanishedAfterTrustError(context.Background(), errors.New("plain error")) {
		t.Fatal("trustedHelperVanishedAfterTrustError = true for plain error")
	}
}

func TestManagerRawSocketUnavailableReportsListeningSocket(t *testing.T) {
	t.Parallel()

	dir, err := os.MkdirTemp("/tmp", "agent-secret-raw-socket-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "daemon.sock")
	addr := net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", &addr)
	unixsocket.SkipIfBindUnavailable(t, err)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()

	manager := Manager{socketPath: path}
	unavailable, err := manager.rawSocketUnavailable(context.Background())
	if err != nil {
		t.Fatalf("rawSocketUnavailable returned error: %v", err)
	}
	if unavailable {
		t.Fatal("rawSocketUnavailable = true for listening socket")
	}
}

func TestSignalProcessReportsCurrentProcessSignalZero(t *testing.T) {
	t.Parallel()

	if err := signalProcess(os.Getpid(), syscall.Signal(0)); err != nil {
		t.Fatalf("signalProcess current process signal 0 returned error: %v", err)
	}
}

func TestManagerSignalTrustedHelperMissingSocketIsNoop(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}
	if err := manager.signalTrustedHelper(context.Background()); err != nil {
		t.Fatalf("signalTrustedHelper returned error: %v", err)
	}
}

func TestManagerStartCurrentWithStatusRetryReturnsNonRetryableError(t *testing.T) {
	t.Parallel()

	manager := Manager{socketPath: filepath.Join(t.TempDir(), "missing.sock")}
	_, err := manager.startCurrentWithStatusRetry(context.Background(), RepairStatusOK)
	if err == nil || !strings.Contains(err.Error(), "daemon path is required") {
		t.Fatalf("startCurrentWithStatusRetry error = %v, want daemon path required", err)
	}
}

func TestManagerWriterUsesConfiguredWriterWhenPresent(t *testing.T) {
	t.Parallel()

	fallback := io.Discard
	configured := strings.Builder{}
	if got := managerWriter(fallback, &configured); got != &configured {
		t.Fatal("managerWriter did not return configured writer")
	}
	if got := managerWriter(fallback, nil); got != fallback {
		t.Fatal("managerWriter did not return fallback writer")
	}
}

func TestManagerRepairRejectsUnexpectedHelper(t *testing.T) {
	t.Parallel()

	path, stop := startFakeExecDaemon(t)
	defer stop()
	manager := Manager{
		socketPath: path,
		DaemonPath: writeDaemonExecutableAt(t, t.TempDir()),
	}

	_, err := manager.Repair(context.Background())
	if !errors.Is(err, ErrUnexpectedHelper) {
		t.Fatalf("Repair error = %v, want %v", err, ErrUnexpectedHelper)
	}
}

func TestManagerInspectConnectedHelperClassifiesLegacyHello(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	path, stop := startFakeStatusErrorDaemon(t, protocol.ErrorCodeBadType)
	defer stop()
	manager := Manager{
		socketPath: path,
		DaemonPath: executable,
	}
	client, err := manager.connectTrustedHelper(context.Background())
	if err != nil {
		t.Fatalf("connectTrustedHelper returned error: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = manager.inspectConnectedHelper(context.Background(), client)
	if !errors.Is(err, ErrHelperMismatch) {
		t.Fatalf("inspectConnectedHelper error = %v, want helper mismatch", err)
	}
}

func TestManagerStopTrustedHelperStopsMatchingSocket(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	path, stop := startFakeHelperDaemon(t, helperidentity.ForExecutable(executable, os.Getpid()))
	defer stop()
	manager := Manager{
		socketPath:     path,
		DaemonPath:     executable,
		StartupTimeout: time.Second,
	}

	if err := manager.stopTrustedHelper(context.Background()); err != nil {
		t.Fatalf("stopTrustedHelper returned error: %v", err)
	}
	if _, err := manager.Status(context.Background()); !errors.Is(err, socket.ErrDaemonUnavailable) {
		t.Fatalf("Status after stop error = %v, want daemon unavailable", err)
	}
}

func TestManagerStopTrustedHelperIgnoresMissingSocket(t *testing.T) {
	t.Parallel()

	manager := Manager{
		socketPath: filepath.Join(t.TempDir(), "missing.sock"),
		DaemonPath: writeDaemonExecutableAt(t, t.TempDir()),
	}

	if err := manager.stopTrustedHelper(context.Background()); err != nil {
		t.Fatalf("stopTrustedHelper returned error: %v", err)
	}
}

func TestManagerTrustedHelperUnavailableStates(t *testing.T) {
	t.Parallel()

	manager := Manager{
		socketPath: filepath.Join(t.TempDir(), "missing.sock"),
		DaemonPath: writeDaemonExecutableAt(t, t.TempDir()),
	}
	unavailable, err := manager.trustedHelperUnavailable(context.Background())
	if err != nil {
		t.Fatalf("trustedHelperUnavailable missing socket returned error: %v", err)
	}
	if !unavailable {
		t.Fatal("trustedHelperUnavailable missing socket = false, want true")
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable returned error: %v", err)
	}
	path, stop := startFakeStatusErrorDaemon(t, protocol.ErrorCodeDaemonStopped)
	defer stop()
	manager = Manager{
		socketPath: path,
		DaemonPath: executable,
	}
	unavailable, err = manager.trustedHelperUnavailable(context.Background())
	if err != nil {
		t.Fatalf("trustedHelperUnavailable retiring helper returned error: %v", err)
	}
	if unavailable {
		t.Fatal("trustedHelperUnavailable retiring helper = true, want false")
	}

	hello := helperidentity.ForExecutable(executable, os.Getpid())
	path, stop = startFakeHelperDaemon(t, hello)
	defer stop()
	manager = Manager{
		socketPath: path,
		DaemonPath: executable,
	}
	unavailable, err = manager.trustedHelperUnavailable(context.Background())
	if err != nil {
		t.Fatalf("trustedHelperUnavailable running helper returned error: %v", err)
	}
	if unavailable {
		t.Fatal("trustedHelperUnavailable running helper = true, want false")
	}
}

func TestManagerHelperMatchesExpectedBuild(t *testing.T) {
	t.Parallel()

	manager := Manager{DaemonPath: writeDaemonBundleExecutableAt(t, t.TempDir(), peertrust.DefaultDaemonBundleID)}
	expected, err := manager.expectedHelperHello()
	if err != nil {
		t.Fatalf("expectedHelperHello returned error: %v", err)
	}

	matches, err := manager.helperMatchesExpected(expected)
	if err != nil {
		t.Fatalf("helperMatchesExpected returned error: %v", err)
	}
	if !matches {
		t.Fatal("helperMatchesExpected returned false for expected helper hello")
	}

	for _, tc := range []struct {
		name   string
		mutate func(*protocol.HelperHelloPayload)
	}{
		{
			name: "protocol",
			mutate: func(hello *protocol.HelperHelloPayload) {
				hello.Protocol++
			},
		},
		{
			name: "app version",
			mutate: func(hello *protocol.HelperHelloPayload) {
				hello.AppVersion = "0.0.0-test"
			},
		},
		{
			name: "build id",
			mutate: func(hello *protocol.HelperHelloPayload) {
				hello.BuildID += "-old"
			},
		},
		{
			name: "executable",
			mutate: func(hello *protocol.HelperHelloPayload) {
				hello.Executable = writeDaemonExecutableAt(t, t.TempDir())
			},
		},
		{
			name: "bundle id",
			mutate: func(hello *protocol.HelperHelloPayload) {
				hello.BundleID = "com.example.agent-secret.daemon"
			},
		},
	} {
		hello := expected
		tc.mutate(&hello)
		matches, err := manager.helperMatchesExpected(hello)
		if err != nil {
			t.Fatalf("%s: helperMatchesExpected returned error: %v", tc.name, err)
		}
		if matches {
			t.Fatalf("%s: helperMatchesExpected returned true for mismatched hello %+v", tc.name, hello)
		}
	}
}

func TestManagerExpectedHelperHelloRequiresDaemonPath(t *testing.T) {
	t.Parallel()

	_, err := (Manager{DaemonPath: " \t "}).expectedHelperHello()
	if err == nil || !strings.Contains(err.Error(), "daemon path is required") {
		t.Fatalf("expectedHelperHello error = %v, want daemon path required", err)
	}
}

func TestClassifyHelperConnectErrorHidesPeerTrustBehindUnexpectedHelper(t *testing.T) {
	t.Parallel()

	err := classifyHelperConnectError(fmt.Errorf("dial helper: %w", peertrust.ErrUntrustedDaemon))
	if !errors.Is(err, ErrUnexpectedHelper) {
		t.Fatalf("classifyHelperConnectError = %v, want unexpected helper", err)
	}
	if !errors.Is(err, peertrust.ErrUntrustedDaemon) {
		t.Fatalf("classifyHelperConnectError = %v, want original peer trust cause", err)
	}
	plainErr := errors.New("plain failure")
	if !errors.Is(classifyHelperConnectError(plainErr), plainErr) {
		t.Fatal("classifyHelperConnectError wrapped a non-peer-trust error")
	}
}

func TestHelperHelloMismatchError(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		protocol.ErrProtocolType,
		protocol.ErrProtocolVersion,
		&ProtocolError{Code: protocol.ErrorCodeBadType, Message: "bad type"},
	} {
		if !helperHelloMismatchError(err) {
			t.Fatalf("helperHelloMismatchError(%v) = false, want true", err)
		}
	}
	if helperHelloMismatchError(errors.New("plain failure")) {
		t.Fatal("plain error was classified as helper hello mismatch")
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

func startFakeHelperDaemon(t *testing.T, hello protocol.HelperHelloPayload) (string, func()) {
	t.Helper()
	return startFakeHelperDaemonWithOptions(t, fakeHelperOptions{hello: hello})
}

type fakeHelperOptions struct {
	hello         protocol.HelperHelloPayload
	stopErrorCode protocol.ErrorCode
}

func startFakeHelperDaemonWithOptions(t *testing.T, opts fakeHelperOptions) (string, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "agent-secret-fake-helper-")
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
	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() {
			_ = listener.Close()
			_ = os.Remove(path)
		})
	}
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go serveFakeHelperDaemonConn(conn, opts, shutdown)
		}
	}()
	return path, func() {
		shutdown()
		<-done
		_ = os.RemoveAll(dir)
	}
}

func serveFakeHelperDaemonConn(
	conn *net.UnixConn,
	opts fakeHelperOptions,
	shutdown func(),
) {
	defer func() { _ = conn.Close() }()
	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	for {
		var env protocol.Envelope
		if err := decoder.Decode(&env); err != nil {
			return
		}
		switch env.Type { //nolint:exhaustive // Fake helper handles only manager repair requests.
		case protocol.TypeHelperHello:
			if !writeFakeHelperResponse(encoder, env.Correlation(), opts.hello) {
				return
			}
		case protocol.TypeDaemonStatus:
			if !writeFakeHelperResponse(encoder, env.Correlation(), protocol.StatusPayload{PID: opts.hello.PID}) {
				return
			}
		case protocol.TypeDaemonStop:
			if opts.stopErrorCode != "" {
				if !writeFakeHelperError(encoder, env.Correlation(), opts.stopErrorCode) {
					return
				}
				return
			}
			if !writeFakeHelperResponse(encoder, env.Correlation(), protocol.StatusPayload{PID: opts.hello.PID}) {
				return
			}
			shutdown()
			return
		default:
			resp, err := protocol.NewEnvelope(protocol.TypeError, env.Correlation(), protocol.ErrorPayload{
				Code:    protocol.ErrorCodeBadType,
				Message: "unsupported fake helper request",
			})
			if err != nil {
				return
			}
			if err := encoder.Encode(resp); err != nil {
				return
			}
		}
	}
}

func writeFakeHelperError(encoder *json.Encoder, correlation protocol.Correlation, code protocol.ErrorCode) bool {
	resp, err := protocol.NewEnvelope(protocol.TypeError, correlation, protocol.ErrorPayload{
		Code:    code,
		Message: "fake helper rejected request",
	})
	if err != nil {
		return false
	}
	return encoder.Encode(resp) == nil
}

func writeFakeHelperResponse(encoder *json.Encoder, correlation protocol.Correlation, payload any) bool {
	resp, err := protocol.NewEnvelope(protocol.TypeOK, correlation, payload)
	if err != nil {
		return false
	}
	return encoder.Encode(resp) == nil
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

func writeDaemonBundleExecutableAt(t *testing.T, dir string, bundleID string) string {
	t.Helper()
	bundlePath := filepath.Join(dir, "AgentSecretDaemon.app")
	macOSPath := filepath.Join(bundlePath, "Contents", "MacOS")
	if err := os.MkdirAll(macOSPath, 0o750); err != nil {
		t.Fatalf("mkdir daemon bundle: %v", err)
	}
	executable := filepath.Join(macOSPath, "agent-secretd")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { //nolint:gosec // G306: daemon control tests need runnable fixture executables.
		t.Fatalf("write bundled executable: %v", err)
	}
	plist := `<plist><dict><key>CFBundleExecutable</key><string>agent-secretd</string>` +
		`<key>CFBundleIdentifier</key><string>` + bundleID + `</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(bundlePath, "Contents", "Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatalf("write Info.plist: %v", err)
	}
	return executable
}
