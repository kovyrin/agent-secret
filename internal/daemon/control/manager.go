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
	inspection, err := m.inspectTrustedHelper(ctx)
	if err == nil {
		if inspection.matches {
			return RepairResult{Status: RepairStatusOK, PID: inspection.hello.PID, Hello: inspection.hello}, nil
		}
		return m.refreshTrustedHelper(ctx)
	}
	if errors.Is(err, socket.ErrDaemonUnavailable) {
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
		return RepairResult{Status: RepairStatusOK, PID: inspection.hello.PID, Hello: inspection.hello}, nil
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
	return RepairResult{Status: RepairStatusRepairRequired}, err
}

func (m Manager) startCurrent(ctx context.Context) error {
	if err := m.statusBeforeStart(ctx); err == nil {
		return nil
	} else if isRetiringDaemon(err) {
		if err := m.waitUntilUnavailable(ctx, 25*time.Millisecond); err != nil {
			return err
		}
	} else if !errors.Is(err, socket.ErrDaemonUnavailable) {
		return err
	}
	if m.DaemonPath == "" {
		return errors.New("daemon path is required")
	}
	if err := socket.PrepareDirectory(m.socketPath); err != nil {
		return err
	}
	if err := socket.CleanupStale(m.socketPath); err != nil {
		return err
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
	if errors.Is(err, peertrust.ErrUntrustedDaemon) {
		return fmt.Errorf("%w: %w", ErrUnexpectedHelper, err)
	}
	return err
}

func helperHelloMismatchError(err error) bool {
	return errors.Is(err, protocol.ErrProtocolType) ||
		errors.Is(err, protocol.ErrProtocolVersion) ||
		IsProtocolError(err, protocol.ErrorCodeBadType)
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
		return err
	}
	_ = client.Close()
	return m.waitUntilTrustedHelperUnavailable(ctx, 25*time.Millisecond)
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
