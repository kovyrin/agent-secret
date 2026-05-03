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
	//nolint:gosec // G703: path is the Unix socket just created after directory validation.
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

func ValidateSocketDirectory(path string) error {
	return rejectInsecureSocketDirectory(filepath.Dir(path))
}

func prepareDefaultSocketDirectory(dir string) error {
	if err := rejectSocketDirectoryAncestry(dir); err != nil {
		return err
	}
	if err := rejectSocketDirectorySymlinkOrOwner(dir); err != nil {
		return err
	}
	//nolint:gosec // G703: dir is the managed default socket directory under Application Support.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	if err := rejectSocketDirectoryAncestry(dir); err != nil {
		return err
	}
	if err := rejectSocketDirectorySymlinkOrOwner(dir); err != nil {
		return err
	}
	//nolint:gosec // G703: only the managed default socket directory is chmodded.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure socket directory: %w", err)
	}
	return rejectInsecureSocketDirectory(dir)
}

func prepareCustomSocketDirectory(dir string) error {
	if err := rejectSocketDirectoryAncestry(dir); err != nil {
		return err
	}
	//nolint:gosec // G703: custom mkdir creates missing private parents but existing parents are validated, not chmodded.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	return rejectInsecureSocketDirectory(dir)
}

func rejectInsecureSocketDirectory(dir string) error {
	if err := rejectSocketDirectoryAncestry(dir); err != nil {
		return err
	}
	info, err := socketDirectoryInfo(dir)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has mode %s", ErrInsecureSocketDirectory, dir, info.Mode().Perm())
	}
	return nil
}

func rejectSocketDirectorySymlinkOrOwner(dir string) error {
	_, err := socketDirectoryInfo(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func socketDirectoryInfo(dir string) (os.FileInfo, error) {
	//nolint:gosec // G703: lstat validates the socket parent itself before use.
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s is a symlink", ErrInsecureSocketDirectory, dir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrInsecureSocketDirectory, dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if ok && int(stat.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrInsecureSocketDirectory, dir, stat.Uid)
	}
	return info, nil
}

func rejectSocketDirectoryAncestry(dir string) error {
	cleanDir := filepath.Clean(dir)
	for current := cleanDir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat socket directory ancestor: %w", err)
		}
		if err == nil {
			if err := rejectSocketDirectoryAncestorInfo(cleanDir, current, info); err != nil {
				return err
			}
		}

		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
	}
}

func rejectSocketDirectoryAncestorInfo(cleanDir, current string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		if isAllowedSocketRootAlias(current) {
			return nil
		}
		return fmt.Errorf("%w: %s contains symlink ancestor %s", ErrInsecureSocketDirectory, cleanDir, current)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s contains non-directory ancestor %s", ErrInsecureSocketDirectory, cleanDir, current)
	}
	return nil
}

func isAllowedSocketRootAlias(path string) bool {
	switch path {
	case "/etc", "/tmp", "/var":
		return true
	default:
		return false
	}
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

func cleanupStaleSocket(path string) error {
	//nolint:gosec // G703: lstat checks whether the configured socket path is a stale Unix socket before removal.
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
	//nolint:gosec // G703: removal is limited to stale Unix socket paths after lstat and failed live-daemon dial.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale daemon socket: %w", err)
	}
	return nil
}
