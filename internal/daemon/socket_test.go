package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestWaitUntilReadyHonorsDefaultIntervalAndTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	err := WaitUntilReady(ctx, filepath.Join(t.TempDir(), "missing.sock"), 0)
	if !errors.Is(err, ErrDaemonUnavailable) {
		t.Fatalf("expected daemon unavailable timeout, got %v", err)
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
