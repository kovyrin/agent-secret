package executabletrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

var ErrMutablePath = errors.New("mutable executable path")

func ValidateStableExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("executable path %q is a directory", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("executable path %q is not executable", path)
	}
	if err := validateStableComponent(path, "executable", info); err != nil {
		return err
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		dirInfo, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("stat executable parent %q: %w", dir, err)
		}
		if !dirInfo.IsDir() {
			return fmt.Errorf("executable parent %q is not a directory", dir)
		}
		if err := validateStableComponent(dir, "executable parent", dirInfo); err != nil {
			return err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}

func validateStableComponent(path string, label string, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return fmt.Errorf("%w: %s %q is group/world writable", ErrMutablePath, label, path)
	}
	if ownedByCurrentUser(info) {
		return fmt.Errorf("%w: %s %q is owned by the current user", ErrMutablePath, label, path)
	}
	return nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return strconv.FormatUint(uint64(stat.Uid), 10) == strconv.Itoa(os.Geteuid())
}
