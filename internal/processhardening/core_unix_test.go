//go:build darwin || linux || freebsd || openbsd || netbsd

package processhardening

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDisableCoreDumps(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatalf("DisableCoreDumps returned error: %v", err)
	}
}

func TestSetCoreDumpLimitDisablesCoreFiles(t *testing.T) {
	t.Parallel()

	var resource int
	var limit unix.Rlimit
	err := setCoreDumpLimit(func(gotResource int, gotLimit *unix.Rlimit) error {
		resource = gotResource
		limit = *gotLimit
		return nil
	})
	if err != nil {
		t.Fatalf("setCoreDumpLimit returned error: %v", err)
	}
	if resource != unix.RLIMIT_CORE {
		t.Fatalf("resource = %d, want RLIMIT_CORE", resource)
	}
	if limit.Cur != 0 || limit.Max != 0 {
		t.Fatalf("limit = {%d, %d}, want {0, 0}", limit.Cur, limit.Max)
	}
}

func TestSetCoreDumpLimitWrapsErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("boom")
	err := setCoreDumpLimit(func(_ int, _ *unix.Rlimit) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want wrapped sentinel", err)
	}
}
