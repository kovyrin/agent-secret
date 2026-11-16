//go:build darwin

package messageauth

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/kovyrin/agent-secret/internal/peercred"
)

func TestPortAttestsExactFrameOnce(t *testing.T) {
	port, err := NewPort()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(port.Close)

	frame := []byte(`{"version":1,"type":"request.exec"}`)
	if err := Send(port.Name(), frame); err != nil {
		t.Fatal(err)
	}
	identity, err := port.Receive(frame, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != os.Getpid() || identity.UID != os.Getuid() || identity.PIDVersion == 0 {
		t.Fatalf("unexpected sender identity: %+v", identity)
	}
	if _, err := port.Receive(frame, 10*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("attestation was reusable: %v", err)
	}

	if err := Send(port.Name(), frame); err != nil {
		t.Fatal(err)
	}
	if _, err := port.Receive([]byte(`{"version":1,"type":"daemon.stop"}`), time.Second); !errors.Is(err, ErrFrameMismatch) {
		t.Fatalf("mismatched frame accepted: %v", err)
	}
}

func TestMachSenderTokenPrecedesExecImage(t *testing.T) {
	if os.Getenv("AGENT_SECRET_TEST_MACOS_PEER_IDENTITY") != "1" {
		t.Skip("set AGENT_SECRET_TEST_MACOS_PEER_IDENTITY=1 for macOS socket credential integration")
	}
	port, err := NewPort()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(port.Close)
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverFile := os.NewFile(uintptr(fds[0]), "server") //nolint:gosec // Socketpair returns nonnegative descriptors.
	childFile := os.NewFile(uintptr(fds[1]), "child")   //nolint:gosec // Socketpair returns nonnegative descriptors.
	defer func() { _ = serverFile.Close() }()
	defer func() { _ = childFile.Close() }()
	serverConn, err := net.FileConn(serverFile)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverConn.Close() }()
	unixConn, ok := serverConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("socketpair connection type = %T, want UnixConn", serverConn)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestMachExecHelper$") //nolint:gosec // Test re-executes its own binary.
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Env = []string{"AGENT_SECRET_AUTH_HELPER=1", "AGENT_SECRET_AUTH_PORT=" + port.Name()}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	_ = childFile.Close()
	if err := unixConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	frame, err := bufio.NewReader(unixConn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	frame = bytes.TrimSuffix(frame, []byte{'\n'})
	identity, err := port.Receive(frame, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var current peercred.Info
	for range 100 {
		current, err = peercred.Inspect(unixConn)
		if err == nil && current.ExecutablePath == "/bin/sleep" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || current.ExecutablePath != "/bin/sleep" {
		t.Fatalf("exec image not observed: path %q, error %v", current.ExecutablePath, err)
	}
	if identity.PID != current.PID || identity.PIDVersion == current.PIDVersion {
		t.Fatalf("Mach sender token did not distinguish pre-exec image: Mach %+v, socket PID %d version %d",
			identity, current.PID, current.PIDVersion)
	}
}

func TestMachExecHelper(t *testing.T) {
	if os.Getenv("AGENT_SECRET_AUTH_HELPER") != "1" {
		return
	}
	frame := []byte(`{"version":1,"type":"request.exec"}`)
	if err := Send(os.Getenv("AGENT_SECRET_AUTH_PORT"), frame); err != nil {
		t.Fatal(err)
	}
	child := os.NewFile(3, "inherited socket")
	if _, err := child.Write(append(frame, '\n')); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Exec("/bin/sleep", []string{"sleep", "2"}, []string{}); err != nil { //nolint:gosec // Fixed system binary exercises image replacement.
		t.Fatal(err)
	}
}
