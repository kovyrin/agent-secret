//go:build darwin

package peercred

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	peerExecHelperEnv   = "AGENT_SECRET_TEST_PEERCRED_EXEC_HELPER"
	peerExecSocketEnv   = "AGENT_SECRET_TEST_PEERCRED_EXEC_SOCKET"
	peerExecHelperWrite = "write"
)

func TestInspectFDRejectsInvalidDescriptor(t *testing.T) {
	t.Parallel()

	_, err := inspectFD(^uintptr(0))
	if err == nil {
		t.Fatal("expected invalid descriptor error")
	}
}

// TestInspectDetectsExecOnConnectedSocket proves the kernel signal the daemon
// relies on to bind a connection to one process image. A helper connects and
// writes before execve, keeps the socket across execve, and the test verifies
// that the peer PID stays the same while the PID version changes.
func TestInspectDetectsExecOnConnectedSocket(t *testing.T) {
	if os.Getenv(peerExecHelperEnv) == peerExecHelperWrite {
		runPeerExecWriteHelper(t)
		return
	}
	if os.Getenv("AGENT_SECRET_TEST_SOCKET_CREDENTIALS") != "1" {
		t.Skip("set AGENT_SECRET_TEST_SOCKET_CREDENTIALS=1 to test live macOS socket credentials")
	}
	if testing.Short() {
		t.Skip("skipping helper process exec test in short mode")
	}

	dir, err := os.MkdirTemp("", "as-peer")
	if err != nil {
		t.Fatalf("create socket directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "peer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen on test socket: %v", err)
	}
	defer func() { _ = listener.Close() }()
	if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set listener deadline: %v", err)
	}

	testExe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.CommandContext( //nolint:gosec // G204: test re-executes its own test binary to exercise execve on a live socket.
		t.Context(),
		testExe,
		"-test.run=^TestInspectDetectsExecOnConnectedSocket$",
	)
	cmd.Env = append(os.Environ(),
		peerExecHelperEnv+"="+peerExecHelperWrite,
		peerExecSocketEnv+"="+path,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatalf("accept helper connection: %v", err)
	}
	defer func() { _ = conn.Close() }()

	accepted, err := Inspect(conn)
	if err != nil {
		t.Fatalf("inspect accepted peer: %v", err)
	}
	if accepted.PID != cmd.Process.Pid {
		t.Fatalf("accepted pid = %d, want helper pid %d", accepted.PID, cmd.Process.Pid)
	}

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read helper readiness: %v", err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatalf("signal helper to exec: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		current, inspectErr := Inspect(conn)
		if inspectErr == nil && current.PID == accepted.PID && current.PIDVersion != accepted.PIDVersion {
			if err := ValidateConnectionPeer(current, accepted); !errors.Is(err, ErrPolicyMismatch) {
				t.Fatalf("ValidateConnectionPeer error = %v, want %v", err, ErrPolicyMismatch)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"peer pid version did not change after exec: accepted pid=%d version=%d current=%+v err=%v",
				accepted.PID,
				accepted.PIDVersion,
				current,
				inspectErr,
			)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runPeerExecWriteHelper(t *testing.T) {
	t.Helper()

	path := os.Getenv(peerExecSocketEnv)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("helper dial: %v", err)
	}
	if err := clearCloseOnExec(conn); err != nil {
		t.Fatalf("helper clear close-on-exec: %v", err)
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		t.Fatalf("helper write readiness: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("helper read go signal: %v", err)
	}

	// Execve keeps the PID and the socket, but replaces the process image.
	exe := "/bin/sleep"
	if _, err := os.Stat(exe); err != nil {
		t.Fatalf("stat %s: %v", exe, err)
	}
	if err := syscall.Exec(exe, []string{"sleep", "2"}, os.Environ()); err != nil { //nolint:gosec // G204: test helper deliberately replaces its image with the fixed /bin/sleep path.
		t.Fatalf("helper exec: %v", err)
	}
}

func clearCloseOnExec(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw connection: %w", err)
	}
	var fcntlErr error
	if err := raw.Control(func(fd uintptr) {
		_, fcntlErr = unix.FcntlInt(fd, unix.F_SETFD, 0)
	}); err != nil {
		return fmt.Errorf("control raw connection: %w", err)
	}
	if fcntlErr != nil {
		return fmt.Errorf("clear close-on-exec: %w", fcntlErr)
	}
	return nil
}
