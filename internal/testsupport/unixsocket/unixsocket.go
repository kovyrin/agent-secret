package unixsocket

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func SkipIfBindUnavailable(tb testing.TB, err error) {
	tb.Helper()
	if err == nil {
		return
	}
	if IsBindUnavailable(err) {
		tb.Skipf("Unix socket bind unavailable in this environment: %v", err)
	}
}

func IsBindUnavailable(err error) bool {
	if errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "bind") &&
		(strings.Contains(message, "operation not permitted") ||
			strings.Contains(message, "permission denied") ||
			strings.Contains(message, "protocol not supported") ||
			strings.Contains(message, "address family not supported"))
}

func Pair(tb testing.TB) (*net.UnixConn, *net.UnixConn) {
	tb.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		tb.Fatalf("create unix socket pair: %v", err)
	}

	left := unixConnFromFD(tb, fds[0], "agent-secret-socketpair-left")
	right := unixConnFromFD(tb, fds[1], "agent-secret-socketpair-right")
	return left, right
}

func unixConnFromFD(tb testing.TB, fd int, name string) *net.UnixConn {
	tb.Helper()

	if fd < 0 {
		tb.Fatalf("invalid unix socket fd %d", fd)
	}
	file := os.NewFile(uintptr(fd), name) //nolint:gosec // G115: fd is a non-negative descriptor returned by unix.Socketpair.
	if file == nil {
		_ = unix.Close(fd)
		tb.Fatalf("wrap unix socket fd %d", fd)
	}
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		tb.Fatalf("create unix connection from fd %d: %v", fd, err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		tb.Fatalf("socket pair fd %d produced %T, want *net.UnixConn", fd, conn)
	}
	return unixConn
}
