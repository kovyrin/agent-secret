//go:build unix

package fileidentity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrMutable = errors.New("mutable executable identity")

func ValidateStableExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable %q: %w", path, err)
	}
	if mutableByCurrentUser(path, info, false) {
		return fmt.Errorf("%w: executable %q is mutable by the current user", ErrMutable, path)
	}

	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("stat executable parent %q: %w", dir, err)
		}
		if mutableByCurrentUser(dir, info, true) {
			return fmt.Errorf("%w: executable parent directory %q is mutable by the current user", ErrMutable, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}

func mutableByCurrentUser(path string, info os.FileInfo, requireSearch bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}

	if int64(stat.Uid) == int64(os.Getuid()) {
		return true
	}

	mode := uint32(unix.W_OK)
	if requireSearch {
		mode |= unix.X_OK
	}
	return unix.Access(path, mode) == nil
}
