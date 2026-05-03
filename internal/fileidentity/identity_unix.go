//go:build unix && !darwin

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
	identity.Device = uint64(stat.Dev)
	identity.Inode = stat.Ino
	return nil
}
