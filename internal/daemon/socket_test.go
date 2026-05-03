package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultSocketPathIgnoresEnvironmentOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_SECRET_SOCKET_PATH", "/tmp/evil.sock")

	path, err := DefaultSocketPath()
	if err != nil {
		t.Fatalf("DefaultSocketPath returned error: %v", err)
	}
	want := filepath.Join(home, "Library", "Application Support", "agent-secret", "agent-secretd.sock")
	if path != want {
		t.Fatalf("default socket path = %q, want %q", path, want)
	}
}

func TestListenUnixCreatesDefaultSocketDirectoryPrivate(t *testing.T) {
	home := shortTempDir(t, "agent-secret-home-")
	t.Setenv("HOME", home)
	path, err := DefaultSocketPath()
	if err != nil {
		t.Fatalf("DefaultSocketPath returned error: %v", err)
	}

	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()

	dirMode := statMode(t, filepath.Dir(path))
	if dirMode != 0o700 {
		t.Fatalf("default socket dir mode = %s, want 0700", dirMode)
	}
	socketMode := statMode(t, path)
	if socketMode != 0o600 {
		t.Fatalf("socket mode = %s, want 0600", socketMode)
	}
}

func TestListenUnixAcceptsPrivateCustomSocketParent(t *testing.T) {
	t.Parallel()

	dir := shortTempDir(t, "agent-secret-socket-")
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: custom socket directories must be owner-searchable and private.
		t.Fatalf("chmod custom dir: %v", err)
	}
	path := filepath.Join(dir, "agent-secretd.sock")

	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()
	if got := statMode(t, dir); got != 0o700 {
		t.Fatalf("custom socket dir mode changed to %s", got)
	}
}

func TestListenUnixRejectsPermissiveCustomSocketParentWithoutChmod(t *testing.T) {
	t.Parallel()

	dir := shortTempDir(t, "agent-secret-socket-")
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: this test intentionally creates a permissive custom socket directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	path := filepath.Join(dir, "agent-secretd.sock")

	listener, err := ListenUnix(path)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if got := statMode(t, dir); got != 0o755 {
		t.Fatalf("custom socket dir mode changed to %s", got)
	}
}

func TestListenUnixRejectsNonSocketPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent-secretd.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fake socket path: %v", err)
	}

	_, err := ListenUnix(path)
	if err == nil {
		t.Fatal("expected non-socket path rejection")
	}
}

func TestCleanupStaleSocketRefusesLiveDaemon(t *testing.T) {
	t.Parallel()

	dir, err := os.MkdirTemp("/tmp", "agent-secret-socket-")
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "agent-secretd.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()

	done := make(chan struct{})
	go func() {
		conn, err := listener.AcceptUnix()
		if err == nil {
			_ = conn.Close()
		}
		close(done)
	}()

	err = cleanupStaleSocket(path)
	if err == nil {
		t.Fatal("expected live daemon socket rejection")
	}
	<-done
}

func statMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func shortTempDir(t *testing.T, pattern string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", pattern)
	if err != nil {
		t.Fatalf("MkdirTemp returned error: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
