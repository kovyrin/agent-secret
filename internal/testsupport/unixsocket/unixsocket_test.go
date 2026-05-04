package unixsocket

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestIsBindUnavailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil},
		{name: "permission sentinel", err: syscall.EPERM, want: true},
		{name: "wrapped access sentinel", err: errors.Join(errors.New("bind failed"), syscall.EACCES), want: true},
		{name: "family sentinel", err: syscall.EAFNOSUPPORT, want: true},
		{name: "protocol sentinel", err: syscall.EPROTONOSUPPORT, want: true},
		{
			name: "bind permission message",
			err:  errors.New("listen unix /tmp/socket: bind: operation not permitted"),
			want: true,
		},
		{
			name: "bind protocol message",
			err:  errors.New("bind: protocol not supported"),
			want: true,
		},
		{
			name: "bind address family message",
			err:  errors.New("bind: address family not supported by protocol family"),
			want: true,
		},
		{name: "different error", err: errors.New("connection refused")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsBindUnavailable(tt.err); got != tt.want {
				t.Fatalf("IsBindUnavailable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestSkipIfBindUnavailable(t *testing.T) {
	t.Parallel()

	SkipIfBindUnavailable(t, nil)

	t.Run("skips unavailable bind", func(t *testing.T) {
		SkipIfBindUnavailable(t, syscall.EPERM)
		t.Fatal("SkipIfBindUnavailable returned after unavailable bind error")
	})
}

func TestPairReturnsConnectedUnixSockets(t *testing.T) {
	t.Parallel()

	left, right := Pair(t)
	t.Cleanup(func() { closeUnixConn(t, left) })
	t.Cleanup(func() { closeUnixConn(t, right) })

	deadline := time.Now().Add(2 * time.Second)
	if err := left.SetDeadline(deadline); err != nil {
		t.Fatalf("set left deadline: %v", err)
	}
	if err := right.SetDeadline(deadline); err != nil {
		t.Fatalf("set right deadline: %v", err)
	}

	want := []byte("agent-secret socketpair")
	if _, err := left.Write(want); err != nil {
		t.Fatalf("write left socket: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(right, got); err != nil {
		t.Fatalf("read right socket: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("right socket read %q, want %q", got, want)
	}
}

func closeUnixConn(t *testing.T, conn *net.UnixConn) {
	t.Helper()

	if err := conn.Close(); err != nil {
		t.Fatalf("close unix conn: %v", err)
	}
}
