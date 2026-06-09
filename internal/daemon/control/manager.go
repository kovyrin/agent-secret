package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	daemonprocess "github.com/kovyrin/agent-secret/internal/daemon/process"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
	"github.com/kovyrin/agent-secret/internal/helperidentity"
	"github.com/kovyrin/agent-secret/internal/pathresolve"
	"github.com/kovyrin/agent-secret/internal/peercred"
)

var ErrDaemonStillRunning = errors.New("daemon still running")
var ErrUnexpectedHelper = errors.New("unexpected background helper")
var ErrHelperMismatch = errors.New("background helper mismatch")

type RepairStatus string

const (
	RepairStatusOK             RepairStatus = "ok"
	RepairStatusRefreshed      RepairStatus = "refreshed"
	RepairStatusRepairRequired RepairStatus = "repair_required"
)

type RepairResult struct {
	Status RepairStatus
	PID    int
	Hello  protocol.HelperHelloPayload
}

type Manager struct {
	socketPath      string
	DaemonPath      string
	DaemonArgs      []string
	StartupTimeout  time.Duration
	ProtocolTimeout time.Duration
	daemonStdout    io.Writer
	daemonStderr    io.Writer
	signalProcess   func(int, os.Signal) error
}

func NewManager(socketPath string) (Manager, error) {
	if socketPath == "" {
		var err error
		socketPath, err = socket.DefaultPath()
		if err != nil {
			return Manager{}, err
		}
	}
	daemonPath, err := daemonprocess.DefaultDaemonPath()
	if err != nil {
		return Manager{}, err
	}
	manager := NewManagerWithSocketPath(socketPath)
	manager.DaemonPath = daemonPath
	return manager, nil
}

func NewManagerWithSocketPath(socketPath string) Manager {
	return Manager{
		socketPath:     socketPath,
		StartupTimeout: 3 * time.Second,
	}
}

func (m Manager) SocketPath() string {
	return m.socketPath
}

func (m Manager) EnsureRunning(ctx context.Context) error {
	_, err := m.Repair(ctx)
	return err
}

func (m Manager) Start(ctx context.Context) error {
	_, err := m.Repair(ctx)
	return err
}

func (m Manager) Repair(ctx context.Context) (RepairResult, error) {
	result, err := m.repairOnce(ctx)
	if err == nil {
		return result, nil
	}
	if !helperUnavailableError(err) && !peerProcessGoneError(err) {
		return result, err
	}
	if waitErr := m.waitUntilUnavailableWith(ctx, 25*time.Millisecond, "trusted helper", m.rawSocketUnavailable); waitErr != nil {
		return result, err
	}
	retryResult, retryErr := m.repairOnce(ctx)
	if retryErr == nil && retryResult.Status == RepairStatusOK && peerProcessGoneError(err) {
		retryResult.Status = RepairStatusRefreshed
	}
	return retryResult, retryErr
}

func (m Manager) repairOnce(ctx context.Context) (RepairResult, error) {
	inspection, err := m.inspectTrustedHelper(ctx)
	if err == nil {
		if inspection.matches {
			return RepairResult{Status: RepairStatusOK, PID: inspection.hello.PID, Hello: inspection.hello}, nil
		}
		return m.refreshTrustedHelper(ctx)
	}
	if helperUnavailableError(err) {
		status := RepairStatusOK
		if peerProcessGoneError(err) {
			status = RepairStatusRefreshed
		}
		return m.startCurrentWithStatusRetry(ctx, status)
	}
	if isRetiringDaemon(err) {
		if err := m.waitUntilTrustedHelperUnavailable(ctx, 25*time.Millisecond); err != nil {
			return RepairResult{Status: RepairStatusRepairRequired}, err
		}
		if err := m.startCurrent(ctx); err != nil {
			return RepairResult{Status: RepairStatusRepairRequired}, err
		}
		inspection, err := m.inspectTrustedHelper(ctx)
		if err != nil {
			return RepairResult{Status: RepairStatusRepairRequired}, err
		}
		if !inspection.matches {
			return RepairResult{Status: RepairStatusRepairRequired, PID: inspection.hello.PID, Hello: inspection.hello},
				fmt.Errorf("%w: refreshed helper still does not match current build", ErrHelperMismatch)
		}
		return RepairResult{Status: RepairStatusRefreshed, PID: inspection.hello.PID, Hello: inspection.hello}, nil
	}
	if errors.Is(err, ErrHelperMismatch) {
		return m.refreshTrustedHelper(ctx)
	}
	if m.trustedHelperVanishedAfterTrustError(ctx, err) {
		return m.startCurrentWithStatusRetry(ctx, RepairStatusRefreshed)
	}
	return RepairResult{Status: RepairStatusRepairRequired}, err
}

func (m Manager) startCurrentWithStatus(ctx context.Context, status RepairStatus) (RepairResult, error) {
	if err := m.startCurrent(ctx); err != nil {
		return RepairResult{Status: RepairStatusRepairRequired}, err
	}
	inspection, err := m.inspectTrustedHelper(ctx)
	if err != nil {
		return RepairResult{Status: RepairStatusRepairRequired}, err
	}
	if !inspection.matches {
		return RepairResult{Status: RepairStatusRepairRequired, PID: inspection.hello.PID, Hello: inspection.hello},
			fmt.Errorf("%w: started helper does not match current build", ErrHelperMismatch)
	}
	return RepairResult{Status: status, PID: inspection.hello.PID, Hello: inspection.hello}, nil
}

func (m Manager) startCurrentWithStatusRetry(ctx context.Context, status RepairStatus) (RepairResult, error) {
	result, err := m.startCurrentWithStatus(ctx, status)
	if err == nil {
		return result, nil
	}
	if !helperUnavailableError(err) && !peerProcessGoneError(err) {
		return result, err
	}
	if waitErr := m.waitUntilUnavailableWith(ctx, 25*time.Millisecond, "trusted helper", m.rawSocketUnavailable); waitErr != nil {
		return result, err
	}
	return m.startCurrentWithStatus(ctx, status)
}

func (m Manager) startCurrent(ctx context.Context) error {
	removePeerGoneSocket := false
	err := m.statusBeforeStart(ctx)
	switch {
	case err == nil:
		return nil
	case isRetiringDaemon(err):
		if err := m.waitUntilUnavailable(ctx, 25*time.Millisecond); err != nil {
			return err
		}
	case peerProcessGoneError(err):
		removePeerGoneSocket = true
	case !helperUnavailableError(err):
		return err
	}
	if m.DaemonPath == "" {
		return errors.New("daemon path is required")
	}
	if err := socket.PrepareDirectory(m.socketPath); err != nil {
		return err
	}
	if removePeerGoneSocket {
		if err := os.Remove(m.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale daemon socket for exited peer: %w", err)
		}
	} else {
		if err := socket.CleanupStale(m.socketPath); err != nil {
			return err
		}
	}

	cmd := daemonprocess.StartCommand(ctx, m.DaemonPath, m.daemonArgs())
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}
	defer func() { _ = devNull.Close() }()
	cmd.Stdin = devNull
	cmd.Stdout = managerWriter(devNull, m.daemonStdout)
	cmd.Stderr = managerWriter(devNull, m.daemonStderr)
	daemonprocess.ConfigureDaemonProcess(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start agent-secretd: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release agent-secretd process: %w", err)
	}

	timeout := m.StartupTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	readyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := m.waitUntilReady(readyCtx, 25*time.Millisecond); err != nil {
		return fmt.Errorf("wait for agent-secretd readiness: %w", err)
	}
	return nil
}

func managerWriter(fallback io.Writer, configured io.Writer) io.Writer {
	if configured != nil {
		return configured
	}
	return fallback
}

func (m Manager) Status(ctx context.Context) (protocol.StatusPayload, error) {
	client, err := m.Connect(ctx)
	if err != nil {
		return protocol.StatusPayload{}, err
	}
	defer func() { _ = client.Close() }()
	return client.Status(ctx)
}

func (m Manager) Stop(ctx context.Context) error {
	client, err := m.Connect(ctx)
	if err != nil {
		return err
	}
	if _, err := client.RequestStop(ctx); err != nil {
		_ = client.Close()
		return err
	}
	_ = client.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		unavailable, err := m.statusUnavailable(ctx)
		if err != nil {
			return err
		}
		if unavailable {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("%w: daemon still responds after stop", ErrDaemonStillRunning)
}

func (m Manager) CheckOnePassword(ctx context.Context, account string) error {
	client, err := m.Connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return client.CheckOnePassword(ctx, account)
}

func (m Manager) Connect(ctx context.Context) (*Client, error) {
	trustedPaths, err := m.trustedDaemonPaths()
	if err != nil {
		return nil, err
	}
	client, err := ConnectWithPeerValidator(ctx, m.socketPath, peertrust.NewDaemonValidator(trustedPaths))
	if err != nil {
		return nil, err
	}
	client.DefaultTimeout = m.protocolTimeout()
	return client, nil
}

func (m Manager) statusBeforeStart(ctx context.Context) error {
	inspection, err := m.inspectCurrentHelper(ctx)
	if err != nil {
		return err
	}
	if !inspection.matches {
		return fmt.Errorf("%w: running helper does not match current build", ErrHelperMismatch)
	}
	return nil
}

func (m Manager) waitUntilReady(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 25 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		err := m.statusBeforeStart(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, socket.ErrDaemonUnavailable) {
			return err
		}
		select {
		case <-ctx.Done():
			ctxErr := ctx.Err()
			if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, ctxErr) {
				ctxErr = errors.Join(ctxErr, cause)
			}
			return fmt.Errorf("%w: authenticated status timeout: %w", socket.ErrDaemonUnavailable, ctxErr)
		case <-ticker.C:
		}
	}
}

func (m Manager) waitUntilUnavailable(ctx context.Context, interval time.Duration) error {
	return m.waitUntilUnavailableWith(ctx, interval, "retiring daemon", m.statusUnavailable)
}

func (m Manager) waitUntilTrustedHelperUnavailable(ctx context.Context, interval time.Duration) error {
	return m.waitUntilUnavailableWith(ctx, interval, "trusted helper", m.trustedHelperUnavailable)
}

func (m Manager) waitUntilUnavailableWith(
	ctx context.Context,
	interval time.Duration,
	label string,
	check func(context.Context) (bool, error),
) error {
	if interval <= 0 {
		interval = 25 * time.Millisecond
	}
	timeout := m.StartupTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		unavailable, err := check(waitCtx)
		if err != nil {
			return err
		}
		if unavailable {
			return nil
		}
		select {
		case <-waitCtx.Done():
			ctxErr := waitCtx.Err()
			if cause := context.Cause(waitCtx); cause != nil && !errors.Is(cause, ctxErr) {
				ctxErr = errors.Join(ctxErr, cause)
			}
			return fmt.Errorf("%w: %s still responds: %w", ErrDaemonStillRunning, label, ctxErr)
		case <-ticker.C:
		}
	}
}

func (m Manager) trustedDaemonPaths() ([]string, error) {
	daemonPath := m.DaemonPath
	if daemonPath == "" {
		var err error
		daemonPath, err = daemonprocess.DefaultDaemonPath()
		if err != nil {
			return nil, err
		}
	}
	return peertrust.DaemonPathsForPath(daemonPath)
}

type helperInspection struct {
	hello   protocol.HelperHelloPayload
	matches bool
}

func (m Manager) inspectCurrentHelper(ctx context.Context) (helperInspection, error) {
	client, err := m.Connect(ctx)
	if err != nil {
		return helperInspection{}, classifyHelperConnectError(err)
	}
	defer func() { _ = client.Close() }()
	return m.inspectConnectedHelper(ctx, client)
}

func (m Manager) inspectTrustedHelper(ctx context.Context) (helperInspection, error) {
	client, err := m.connectTrustedHelper(ctx)
	if err != nil {
		return helperInspection{}, classifyHelperConnectError(err)
	}
	defer func() { _ = client.Close() }()
	return m.inspectConnectedHelper(ctx, client)
}

func (m Manager) inspectConnectedHelper(ctx context.Context, client *Client) (helperInspection, error) {
	hello, err := client.Hello(ctx)
	if err != nil {
		if helperHelloMismatchError(err) {
			return helperInspection{}, fmt.Errorf("%w: %w", ErrHelperMismatch, err)
		}
		return helperInspection{}, err
	}
	matches, err := m.helperMatchesExpected(hello)
	if err != nil {
		return helperInspection{}, err
	}
	return helperInspection{hello: hello, matches: matches}, nil
}

func (m Manager) connectTrustedHelper(ctx context.Context) (*Client, error) {
	trustedPaths, err := m.trustedDaemonPaths()
	if err != nil {
		return nil, err
	}
	client, err := ConnectWithPeerValidator(ctx, m.socketPath, peertrust.NewDaemonProductValidator(trustedPaths))
	if err != nil {
		return nil, err
	}
	client.DefaultTimeout = m.protocolTimeout()
	return client, nil
}

func classifyHelperConnectError(err error) error {
	if peerProcessGoneError(err) {
		return fmt.Errorf("%w: %w", socket.ErrDaemonUnavailable, err)
	}
	if errors.Is(err, peertrust.ErrUntrustedDaemon) {
		return fmt.Errorf("%w: %w", ErrUnexpectedHelper, err)
	}
	return err
}

func helperHelloMismatchError(err error) bool {
	return errors.Is(err, protocol.ErrProtocolType) ||
		errors.Is(err, protocol.ErrProtocolVersion) ||
		IsProtocolError(err, protocol.ErrorCodeBadType) ||
		IsProtocolError(err, protocol.ErrorCodeUntrustedClient)
}

func (m Manager) helperMatchesExpected(hello protocol.HelperHelloPayload) (bool, error) {
	expected, err := m.expectedHelperHello()
	if err != nil {
		return false, err
	}
	if hello.Protocol != expected.Protocol ||
		hello.AppVersion != expected.AppVersion ||
		hello.BuildID != expected.BuildID {
		return false, nil
	}
	if !samePath(hello.Executable, expected.Executable) {
		return false, nil
	}
	if expected.TeamID != "" && hello.TeamID != expected.TeamID {
		return false, nil
	}
	if expected.BundleID != "" && hello.BundleID != expected.BundleID {
		return false, nil
	}
	return true, nil
}

func (m Manager) expectedHelperHello() (protocol.HelperHelloPayload, error) {
	trustedPaths, err := m.trustedDaemonPaths()
	if err != nil {
		return protocol.HelperHelloPayload{}, err
	}
	if len(trustedPaths) == 0 {
		return protocol.HelperHelloPayload{}, errors.New("daemon path is required")
	}
	return helperidentity.ForExecutable(trustedPaths[0], os.Getpid()), nil
}

func samePath(a string, b string) bool {
	return pathresolve.BestEffort(a) == pathresolve.BestEffort(b)
}

func (m Manager) refreshTrustedHelper(ctx context.Context) (RepairResult, error) {
	if err := m.stopTrustedHelper(ctx); err != nil {
		return RepairResult{Status: RepairStatusRepairRequired}, err
	}
	if err := m.startCurrent(ctx); err != nil {
		return RepairResult{Status: RepairStatusRepairRequired}, err
	}
	inspection, err := m.inspectTrustedHelper(ctx)
	if err != nil {
		return RepairResult{Status: RepairStatusRepairRequired}, err
	}
	if !inspection.matches {
		return RepairResult{Status: RepairStatusRepairRequired, PID: inspection.hello.PID, Hello: inspection.hello},
			fmt.Errorf("%w: refreshed helper still does not match current build", ErrHelperMismatch)
	}
	return RepairResult{Status: RepairStatusRefreshed, PID: inspection.hello.PID, Hello: inspection.hello}, nil
}

func (m Manager) stopTrustedHelper(ctx context.Context) error {
	client, err := m.connectTrustedHelper(ctx)
	if errors.Is(err, socket.ErrDaemonUnavailable) {
		return nil
	}
	if err != nil {
		return classifyHelperConnectError(err)
	}
	if _, err := client.RequestStop(ctx); err != nil {
		_ = client.Close()
		if IsProtocolError(err, protocol.ErrorCodeUntrustedClient) {
			return m.signalTrustedHelper(ctx)
		}
		return err
	}
	_ = client.Close()
	return m.waitUntilTrustedHelperUnavailable(ctx, 25*time.Millisecond)
}

func (m Manager) signalTrustedHelper(ctx context.Context) error {
	info, err := m.inspectTrustedHelperPeer(ctx)
	if errors.Is(err, socket.ErrDaemonUnavailable) {
		return nil
	}
	if peerProcessGoneError(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.PID <= 0 {
		return fmt.Errorf("%w: trusted helper pid is unavailable", ErrUnexpectedHelper)
	}
	signalFn := m.signalProcess
	if signalFn == nil {
		signalFn = signalProcess
	}
	if err := signalFn(info.PID, syscall.SIGTERM); err != nil {
		return fmt.Errorf("signal trusted helper pid %d: %w", info.PID, err)
	}
	return m.waitUntilTrustedHelperUnavailable(ctx, 25*time.Millisecond)
}

func (m Manager) inspectTrustedHelperPeer(ctx context.Context) (peercred.Info, error) {
	trustedPaths, err := m.trustedDaemonPaths()
	if err != nil {
		return peercred.Info{}, err
	}
	conn, err := socket.Dial(ctx, m.socketPath)
	if err != nil {
		return peercred.Info{}, err
	}
	defer func() { _ = conn.Close() }()
	info, err := peercred.Inspect(conn)
	if err != nil {
		return peercred.Info{}, fmt.Errorf("%w: inspect daemon peer: %w", peertrust.ErrUntrustedDaemon, err)
	}
	if err := peertrust.NewDaemonProductValidator(trustedPaths).ValidateDaemonPeer(info); err != nil {
		return peercred.Info{}, err
	}
	return info, nil
}

func peerProcessGoneError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ESRCH) || strings.Contains(err.Error(), "no such process")
}

func signalProcess(pid int, sig os.Signal) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Signal(sig); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return nil
}

func (m Manager) trustedHelperVanishedAfterTrustError(ctx context.Context, err error) bool {
	if !errors.Is(err, ErrUnexpectedHelper) && !errors.Is(err, peertrust.ErrUntrustedDaemon) {
		return false
	}
	unavailable, unavailableErr := m.rawSocketUnavailable(ctx)
	if unavailableErr == nil && unavailable {
		return true
	}
	if peerProcessGoneError(err) {
		return m.waitUntilUnavailableWith(ctx, 25*time.Millisecond, "trusted helper", m.rawSocketUnavailable) == nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	return m.waitUntilUnavailableWith(waitCtx, 25*time.Millisecond, "trusted helper", m.rawSocketUnavailable) == nil
}

func (m Manager) rawSocketUnavailable(ctx context.Context) (bool, error) {
	conn, err := socket.Dial(ctx, m.socketPath)
	if err != nil {
		if isUnavailableDaemonStatusError(err) {
			return true, nil
		}
		return false, err
	}
	_ = conn.Close()
	return false, nil
}

func (m Manager) protocolTimeout() time.Duration {
	if m.ProtocolTimeout > 0 {
		return m.ProtocolTimeout
	}
	return DefaultClientProtocolTimeout
}

func (m Manager) statusUnavailable(ctx context.Context) (bool, error) {
	_, err := m.Status(ctx)
	if err == nil {
		return false, nil
	}
	if isUnavailableDaemonStatusError(err) {
		return true, nil
	}
	if isRetiringDaemon(err) {
		return false, nil
	}
	return false, err
}

func (m Manager) trustedHelperUnavailable(ctx context.Context) (bool, error) {
	client, err := m.connectTrustedHelper(ctx)
	if err != nil {
		if isUnavailableDaemonStatusError(err) {
			return true, nil
		}
		return false, classifyHelperConnectError(err)
	}
	defer func() { _ = client.Close() }()
	_, err = client.Status(ctx)
	if err == nil {
		return false, nil
	}
	if isUnavailableDaemonStatusError(err) {
		return true, nil
	}
	if isRetiringDaemon(err) {
		return false, nil
	}
	return false, err
}

func isRetiringDaemon(err error) bool {
	return IsProtocolError(err, protocol.ErrorCodeDaemonStopped)
}

func isUnavailableDaemonStatusError(err error) bool {
	return errors.Is(err, socket.ErrDaemonUnavailable) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}

func helperUnavailableError(err error) bool {
	return isUnavailableDaemonStatusError(err) ||
		(peerProcessGoneError(err) && strings.Contains(err.Error(), socket.ErrDaemonUnavailable.Error()))
}

func (m Manager) daemonArgs() []string {
	if len(m.DaemonArgs) == 0 {
		return []string{"--socket", m.socketPath}
	}
	args := make([]string, 0, len(m.DaemonArgs))
	for _, arg := range m.DaemonArgs {
		args = append(args, strings.ReplaceAll(arg, "{socket}", m.socketPath))
	}
	return args
}
