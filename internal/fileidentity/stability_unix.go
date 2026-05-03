//go:build unix

package fileidentity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

var ErrMutable = errors.New("mutable executable identity")

func ValidateStableExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable %q: %w", path, err)
	}
	if writableByCurrentUser(info, false) {
		return fmt.Errorf("%w: executable %q is writable by the current user", ErrMutable, path)
	}

	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("stat executable parent %q: %w", dir, err)
		}
		if writableByCurrentUser(info, true) {
			return fmt.Errorf("%w: executable parent directory %q is writable by the current user", ErrMutable, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}

func writableByCurrentUser(info os.FileInfo, requireSearch bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}

	mode := info.Mode().Perm()
	uid := os.Getuid()
	gids := currentGroups()

	if int64(stat.Uid) == int64(uid) {
		return modeAllowsWrite(mode, 0o200, 0o100, requireSearch)
	}
	if slices.ContainsFunc(gids, func(gid int) bool { return int64(stat.Gid) == int64(gid) }) {
		return modeAllowsWrite(mode, 0o020, 0o010, requireSearch)
	}
	return modeAllowsWrite(mode, 0o002, 0o001, requireSearch)
}

func currentGroups() []int {
	groups, err := os.Getgroups()
	if err != nil {
		return nil
	}
	out := make([]int, 0, len(groups))
	for _, group := range groups {
		if group >= 0 {
			out = append(out, group)
		}
	}
	return out
}

func modeAllowsWrite(mode os.FileMode, write os.FileMode, search os.FileMode, requireSearch bool) bool {
	if mode&write == 0 {
		return false
	}
	return !requireSearch || mode&search != 0
}
