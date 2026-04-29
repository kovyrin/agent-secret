package peercred

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

func TestInspectRequiresUnixConnection(t *testing.T) {
	t.Parallel()

	_, err := Inspect(nil)
	if err == nil {
		t.Fatal("expected nil connection error")
	}
}

func TestInspectRejectsUninitializedUnixConnection(t *testing.T) {
	t.Parallel()

	_, err := Inspect(&net.UnixConn{})
	if err == nil {
		t.Fatal("expected uninitialized connection error")
	}
}

func TestPeerCredRejectsSpecificMismatches(t *testing.T) {
	t.Parallel()

	expected, err := CurrentExpected()
	if err != nil {
		t.Fatalf("current expected peer: %v", err)
	}
	info := Info(expected)

	tests := []struct {
		name string
		info Info
		want string
	}{
		{name: "uid", info: withUID(info, expected.UID+1), want: "uid"},
		{name: "gid", info: withGID(info, expected.GID+1), want: "gid"},
		{name: "executable", info: withExecutable(info, filepath.Join(t.TempDir(), "other-tool")), want: "executable"},
		{name: "cwd", info: withCWD(info, filepath.Join(t.TempDir(), "other-cwd")), want: "cwd"},
	}

	for _, tt := range tests {
		err := Validate(tt.info, expected)
		if !errors.Is(err, ErrPolicyMismatch) {
			t.Fatalf("%s: expected policy mismatch, got %v", tt.name, err)
		}
		if !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%s: mismatch error %q did not mention %q", tt.name, err, tt.want)
		}
	}
}

func TestComparablePathResolvesSymlinks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink target: %v", err)
	}

	got, err := comparablePath(link)
	if err != nil {
		t.Fatalf("comparablePath returned error: %v", err)
	}
	want, err := comparablePath(target)
	if err != nil {
		t.Fatalf("comparablePath target returned error: %v", err)
	}
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestCurrentExpectedWrapsOSErrors(t *testing.T) {
	t.Parallel()

	boom := errors.New("boom")
	_, err := currentExpected(func() (string, error) {
		return "", boom
	}, os.Getwd)
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("executable error = %v", err)
	}

	_, err = currentExpected(func() (string, error) {
		return "/bin/tool", nil
	}, func() (string, error) {
		return "", boom
	})
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "cwd") {
		t.Fatalf("cwd error = %v", err)
	}
}

func withUID(info Info, uid int) Info {
	info.UID = uid
	return info
}

func withGID(info Info, gid int) Info {
	info.GID = gid
	return info
}

func withExecutable(info Info, path string) Info {
	info.ExecutablePath = path
	return info
}

func withCWD(info Info, path string) Info {
	info.CWD = path
	return info
}
