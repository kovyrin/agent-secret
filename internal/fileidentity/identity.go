package fileidentity

import (
	"errors"
	"fmt"
	"os"
)

var (
	ErrMismatch = errors.New("file identity mismatch")
	ErrMissing  = errors.New("file identity missing")
)

type Identity struct {
	Device             uint64
	Inode              uint64
	Mode               uint32
	Size               int64
	ModTimeUnixNano    int64
	ChangeTimeUnixNano int64
}

func (i Identity) IsZero() bool {
	return i == Identity{}
}

func Capture(path string) (Identity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Identity{}, fmt.Errorf("stat executable identity %q: %w", path, err)
	}
	identity := Identity{
		Mode:            uint32(info.Mode().Perm()),
		Size:            info.Size(),
		ModTimeUnixNano: info.ModTime().UnixNano(),
	}
	if err := addPlatformIdentity(&identity, info); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func Verify(path string, expected Identity) error {
	if expected.IsZero() {
		return ErrMissing
	}
	actual, err := Capture(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("%w: executable %q changed after approval", ErrMismatch, path)
	}
	return nil
}
