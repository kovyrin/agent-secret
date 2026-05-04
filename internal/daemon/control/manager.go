package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kovyrin/agent-secret/internal/daemon/peertrust"
	daemonprocess "github.com/kovyrin/agent-secret/internal/daemon/process"
	"github.com/kovyrin/agent-secret/internal/daemon/protocol"
	"github.com/kovyrin/agent-secret/internal/daemon/socket"
)

var ErrDaemonStillRunning = errors.New("daemon still running")

type Manager struct {
	SocketPath      string
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
	return Manager{
		SocketPath:     socketPath,
		DaemonPath:     daemonPath,
		StartupTimeout: 3 * time.Second,
	}, nil
}

func (m Manager) EnsureRunning(ctx context.Context) error {
	if err := m.statusBeforeStart(ctx); err == nil {
		return nil
	} else if !errors.Is(err, socket.ErrDaemonUnavailable) {
		return err
	}
	if err := m.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (m Manager) Start(ctx context.Context) error {
	if err := m.statusBeforeStart(ctx); err == nil {
		return nil
	} else if !errors.Is(err, socket.ErrDaemonUnavailable) {
		return err
	}
	if m.DaemonPath == "" {
		return errors.New("daemon path is required")
	}
	if err := socket.PrepareDirectory(m.SocketPath); err != nil {
		return err
	}
	if err := socket.CleanupStale(m.SocketPath); err != nil {
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
	if _, err := client.Stop(ctx); err != nil {
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

func (m Manager) CheckOnePassword(ctx context.Context) error {
	client, err := m.Connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return client.CheckOnePassword(ctx)
}

func (m Manager) Connect(ctx context.Context) (*Client, error) {
	trustedPaths, err := m.trustedDaemonPaths()
	if err != nil {
		return nil, err
	}
	client, err := ConnectWithPeerValidator(ctx, m.SocketPath, peertrust.NewDaemonValidator(trustedPaths))
	if err != nil {
		return nil, err
	}
	client.DefaultTimeout = m.protocolTimeout()
	return client, nil
}

func (m Manager) statusBeforeStart(ctx context.Context) error {
	_, err := m.Status(ctx)
	return err
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
			return fmt.Errorf("%w: authenticated status timeout", socket.ErrDaemonUnavailable)
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
	if errors.Is(err, socket.ErrDaemonUnavailable) || errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}

func (m Manager) daemonArgs() []string {
	if len(m.DaemonArgs) == 0 {
		return []string{"--socket", m.SocketPath}
	}
	args := make([]string, 0, len(m.DaemonArgs))
	for _, arg := range m.DaemonArgs {
		args = append(args, strings.ReplaceAll(arg, "{socket}", m.SocketPath))
	}
	return args
}
