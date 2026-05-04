package socket

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/kovyrin/agent-secret/internal/testsupport/testfs"
	"github.com/kovyrin/agent-secret/internal/testsupport/unixsocket"
)

func TestDefaultPathIgnoresEnvironmentOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENT_SECRET_SOCKET_PATH", "/tmp/evil.sock")

	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath returned error: %v", err)
	}
	want := filepath.Join(home, "Library", "Application Support", "agent-secret", "agent-secretd.sock")
	if path != want {
		t.Fatalf("default socket path = %q, want %q", path, want)
	}
}

func listenUnixForTest(t *testing.T, path string) (*net.UnixListener, error) {
	t.Helper()
	listener, err := ListenUnix(path)
	unixsocket.SkipIfBindUnavailable(t, err)
	return listener, err
}

func TestListenUnixCreatesDefaultSocketDirectoryPrivate(t *testing.T) {
	home := testfs.ShortTempDir(t, "agent-secret-home-")
	t.Setenv("HOME", home)
	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath returned error: %v", err)
	}

	listener, err := listenUnixForTest(t, path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()

	dirMode := testfs.StatMode(t, filepath.Dir(path))
	if dirMode != 0o700 {
		t.Fatalf("default socket dir mode = %s, want 0700", dirMode)
	}
	socketMode := testfs.StatMode(t, path)
	if socketMode != 0o600 {
		t.Fatalf("socket mode = %s, want 0600", socketMode)
	}
}

func TestListenUnixRejectsSymlinkDefaultSocketDirectoryWithoutChmodTarget(t *testing.T) {
	home := testfs.ShortTempDir(t, "agent-secret-home-")
	t.Setenv("HOME", home)
	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath returned error: %v", err)
	}
	target := testfs.ShortTempDir(t, "agent-secret-socket-target-")
	if err := os.Chmod(target, 0o755); err != nil { //nolint:gosec // G302: test target is intentionally permissive to prove chmod does not follow the symlink.
		t.Fatalf("chmod target: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(path)), 0o700); err != nil {
		t.Fatalf("create app support dir: %v", err)
	}
	if err := os.Symlink(target, filepath.Dir(path)); err != nil {
		t.Fatalf("symlink default socket dir: %v", err)
	}

	listener, err := listenUnixForTest(t, path)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if got := testfs.StatMode(t, target); got != 0o755 {
		t.Fatalf("symlink target mode = %s, want unchanged 0755", got)
	}
}

func TestListenUnixRejectsSymlinkDefaultSocketAncestorBeforeMkdirAll(t *testing.T) {
	home := testfs.ShortTempDir(t, "agent-secret-home-")
	t.Setenv("HOME", home)
	path, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath returned error: %v", err)
	}
	target := testfs.ShortTempDir(t, "agent-secret-socket-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: test target is intentionally private.
		t.Fatalf("chmod target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(home, "Library")); err != nil {
		t.Fatalf("symlink default socket ancestor: %v", err)
	}

	listener, err := listenUnixForTest(t, path)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "Application Support")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("MkdirAll followed symlinked default ancestor: %v", err)
	}
}

func TestListenUnixAcceptsPrivateCustomSocketParent(t *testing.T) {
	t.Parallel()

	dir := testfs.ShortTempDir(t, "agent-secret-socket-")
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: custom socket directories must be owner-searchable and private.
		t.Fatalf("chmod custom dir: %v", err)
	}
	path := filepath.Join(dir, "agent-secretd.sock")

	listener, err := listenUnixForTest(t, path)
	if err != nil {
		t.Fatalf("ListenUnix returned error: %v", err)
	}
	defer func() { _ = listener.Close() }()
	if got := testfs.StatMode(t, dir); got != 0o700 {
		t.Fatalf("custom socket dir mode changed to %s", got)
	}
}

func TestListenUnixRejectsSymlinkCustomSocketParent(t *testing.T) {
	t.Parallel()

	target := testfs.ShortTempDir(t, "agent-secret-socket-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: custom socket targets are private in this test.
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(testfs.ShortTempDir(t, "agent-secret-socket-parent-"), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink custom socket dir: %v", err)
	}
	path := filepath.Join(link, "agent-secretd.sock")

	listener, err := listenUnixForTest(t, path)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "agent-secretd.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket in symlink target exists or stat failed: %v", err)
	}
}

func TestListenUnixRejectsSymlinkCustomSocketAncestorBeforeMkdirAll(t *testing.T) {
	t.Parallel()

	target := testfs.ShortTempDir(t, "agent-secret-socket-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: custom socket targets are private in this test.
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(testfs.ShortTempDir(t, "agent-secret-socket-parent-"), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink custom socket ancestor: %v", err)
	}
	path := filepath.Join(link, "nested", "agent-secretd.sock")

	listener, err := listenUnixForTest(t, path)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "nested")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("MkdirAll followed symlinked custom ancestor: %v", err)
	}
}

func TestValidateSocketDirectoryForPathRejectsSymlinkParent(t *testing.T) {
	t.Parallel()

	target := testfs.ShortTempDir(t, "agent-secret-socket-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: custom socket targets are private in this test.
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(testfs.ShortTempDir(t, "agent-secret-socket-parent-"), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink socket dir: %v", err)
	}

	err := ValidateSocketDirectoryForPath(filepath.Join(link, "agent-secretd.sock"))
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
}

func TestValidateSocketDirectoryForPathRejectsSymlinkAncestor(t *testing.T) {
	t.Parallel()

	target := testfs.ShortTempDir(t, "agent-secret-socket-target-")
	if err := os.Chmod(target, 0o700); err != nil { //nolint:gosec // G302: custom socket targets are private in this test.
		t.Fatalf("chmod target: %v", err)
	}
	link := filepath.Join(testfs.ShortTempDir(t, "agent-secret-socket-parent-"), "socket-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink socket ancestor: %v", err)
	}

	err := ValidateSocketDirectoryForPath(filepath.Join(link, "nested", "agent-secretd.sock"))
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
}

func TestListenUnixRejectsPermissiveCustomSocketParentWithoutChmod(t *testing.T) {
	t.Parallel()

	dir := testfs.ShortTempDir(t, "agent-secret-socket-")
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: this test intentionally creates a permissive custom socket directory.
		t.Fatalf("chmod custom dir: %v", err)
	}
	path := filepath.Join(dir, "agent-secretd.sock")

	listener, err := listenUnixForTest(t, path)
	if listener != nil {
		_ = listener.Close()
	}
	if !errors.Is(err, ErrInsecureSocketDirectory) {
		t.Fatalf("expected insecure socket directory error, got %v", err)
	}
	if got := testfs.StatMode(t, dir); got != 0o755 {
		t.Fatalf("custom socket dir mode changed to %s", got)
	}
}

func TestListenUnixRejectsNonSocketPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "agent-secretd.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write fake socket path: %v", err)
	}

	_, err := listenUnixForTest(t, path)
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
	listener, err := listenUnixForTest(t, path)
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

	err = CleanupStale(path)
	if err == nil {
		t.Fatal("expected live daemon socket rejection")
	}
	<-done
}
