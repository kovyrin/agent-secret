//go:build darwin

package fileidentity

import (
	"fmt"
	"os"
	"syscall"
)

func addPlatformIdentity(identity *Identity, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: executable stat metadata unavailable", ErrMissing)
	}
	if stat.Dev < 0 {
		return fmt.Errorf("%w: executable device id is negative", ErrMissing)
	}
	identity.Device = uint64(stat.Dev)
	identity.Inode = stat.Ino
	identity.ChangeTimeUnixNano = stat.Ctimespec.Sec*1_000_000_000 + stat.Ctimespec.Nsec
	return nil
}
