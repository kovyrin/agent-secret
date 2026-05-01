//go:build darwin || linux || freebsd || openbsd || netbsd

package processhardening

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func DisableCoreDumps() error {
	if err := setCoreDumpLimit(unix.Setrlimit); err != nil {
		return err
	}
	return nil
}

func setCoreDumpLimit(setrlimit func(int, *unix.Rlimit) error) error {
	if err := setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	return nil
}
