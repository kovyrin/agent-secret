package unixsocket

import (
	"errors"
	"strings"
	"syscall"
	"testing"
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
