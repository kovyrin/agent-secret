package peercred

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPeerCredCapturesCurrentProcess(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(
		os.TempDir(),
		"as-peer-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".sock",
	)
	defer func() { _ = os.Remove(socketPath) }()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan *net.UnixConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer func() { _ = client.Close() }()

	var server *net.UnixConn
	select {
	case err := <-acceptErr:
		t.Fatalf("accept unix: %v", err)
	case server = <-accepted:
		defer func() { _ = server.Close() }()
	}

	info, err := Inspect(server)
	if errors.Is(err, ErrUnsupportedOS) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatalf("inspect peer credentials: %v", err)
	}

	expected, err := CurrentExpected()
	if err != nil {
		t.Fatalf("current expected peer: %v", err)
	}

	if err := Validate(info, expected); err != nil {
		t.Fatalf("validate peer credentials: %v\ninfo=%+v\nexpected=%+v", err, info, expected)
	}
}

func TestPeerCredRejectsMismatchedPolicy(t *testing.T) {
	t.Parallel()

	expected, err := CurrentExpected()
	if err != nil {
		t.Fatalf("current expected peer: %v", err)
	}

	info := Info{
		UID:            os.Getuid(),
		GID:            os.Getgid(),
		PID:            os.Getpid(),
		ExecutablePath: expected.ExecutablePath,
		CWD:            expected.CWD,
	}

	wrongPID := expected
	wrongPID.PID++

	if err := Validate(info, wrongPID); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("expected policy mismatch, got %v", err)
	}
}

func TestPeerCredRejectsMissingMetadata(t *testing.T) {
	t.Parallel()

	expected, err := CurrentExpected()
	if err != nil {
		t.Fatalf("current expected peer: %v", err)
	}

	err = Validate(Info{UID: os.Getuid(), GID: os.Getgid(), PID: os.Getpid()}, expected)
	if !errors.Is(err, ErrMissingMetadata) {
		t.Fatalf("expected missing metadata, got %v", err)
	}
}
