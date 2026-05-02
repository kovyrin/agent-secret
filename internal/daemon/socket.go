package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var (
	ErrDaemonUnavailable       = errors.New("daemon unavailable")
	ErrInsecureSocketDirectory = errors.New("insecure daemon socket directory")
)

func DefaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "agent-secret", "agent-secretd.sock"), nil
}

func ListenUnix(path string) (*net.UnixListener, error) {
	if err := prepareSocketDirectory(path); err != nil {
		return nil, err
	}
	if err := cleanupStaleSocket(path); err != nil {
		return nil, err
	}

	addr := net.UnixAddr{Name: path, Net: "unix"}
	listener, err := net.ListenUnix("unix", &addr)
	if err != nil {
		return nil, fmt.Errorf("listen on daemon socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("secure daemon socket: %w", err)
	}
	return listener, nil
}

func prepareSocketDirectory(path string) error {
	defaultPath, err := DefaultSocketPath()
	if err == nil && filepath.Clean(path) == filepath.Clean(defaultPath) {
		return prepareDefaultSocketDirectory(filepath.Dir(path))
	}
	return prepareCustomSocketDirectory(filepath.Dir(path))
}

func prepareDefaultSocketDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure socket directory: %w", err)
	}
	return nil
}

func prepareCustomSocketDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	return rejectInsecureSocketDirectory(dir)
}

func rejectInsecureSocketDirectory(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat socket directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecureSocketDirectory, dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureSocketDirectory, dir, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrInsecureSocketDirectory, dir, stat.Uid)
	}
	return nil
}

func Dial(ctx context.Context, path string) (*net.UnixConn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDaemonUnavailable, err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("daemon socket did not return unix connection")
	}
	return unixConn, nil
}

func WaitUntilReady(ctx context.Context, path string, interval time.Duration) error {
	if interval <= 0 {
		interval = 25 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		conn, err := Dial(ctx, path)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: socket readiness timeout", ErrDaemonUnavailable)
		case <-ticker.C:
		}
	}
}

func cleanupStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat daemon socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove non-socket path %s", path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	conn, err := Dial(ctx, path)
	if err == nil {
		_ = conn.Close()
		return fmt.Errorf("daemon already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale daemon socket: %w", err)
	}
	return nil
}
