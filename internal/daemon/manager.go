package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Manager struct {
	SocketPath     string
	DaemonPath     string
	DaemonArgs     []string
	StartupTimeout time.Duration
}

func NewManager(socketPath string) (Manager, error) {
	if socketPath == "" {
		var err error
		socketPath, err = DefaultSocketPath()
		if err != nil {
			return Manager{}, err
		}
	}
	if daemonPath := strings.TrimSpace(os.Getenv("AGENT_SECRET_DAEMON_PATH")); daemonPath != "" {
		return Manager{
			SocketPath:     socketPath,
			DaemonPath:     daemonPath,
			StartupTimeout: 3 * time.Second,
		}, nil
	}
	daemonPath, err := defaultDaemonPath()
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
	if _, err := m.Status(ctx); err == nil {
		return nil
	}
	if err := m.Start(ctx); err != nil {
		return err
	}
	return nil
}

func (m Manager) Start(ctx context.Context) error {
	if _, err := m.Status(ctx); err == nil {
		return nil
	}
	if m.DaemonPath == "" {
		return errors.New("daemon path is required")
	}
	if err := os.MkdirAll(filepath.Dir(m.SocketPath), 0o700); err != nil {
		return fmt.Errorf("create daemon socket directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(m.SocketPath), 0o700); err != nil {
		return fmt.Errorf("secure daemon socket directory: %w", err)
	}
	_ = cleanupStaleSocket(m.SocketPath)

	cmd := daemonStartCommand(ctx, m.DaemonPath, m.daemonArgs())
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}
	defer devNull.Close()
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	configureDaemonProcess(cmd)
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
	if err := WaitUntilReady(readyCtx, m.SocketPath, 25*time.Millisecond); err != nil {
		return fmt.Errorf("wait for agent-secretd readiness: %w", err)
	}
	return nil
}

func (m Manager) Status(ctx context.Context) (StatusPayload, error) {
	client, err := Connect(ctx, m.SocketPath)
	if err != nil {
		return StatusPayload{}, err
	}
	defer client.Close()
	return client.Status(ctx)
}

func (m Manager) Stop(ctx context.Context) error {
	client, err := Connect(ctx, m.SocketPath)
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
		if _, err := m.Status(ctx); err != nil {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("%w: daemon still responds after stop", ErrDaemonUnavailable)
}

func (m Manager) Connect(ctx context.Context) (*Client, error) {
	return Connect(ctx, m.SocketPath)
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

func defaultDaemonPath() (string, error) {
	if appPath, ok := defaultDaemonAppPath(); ok {
		return appPath, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get current executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), "agent-secretd"), nil
}
