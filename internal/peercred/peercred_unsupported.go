//go:build !darwin

package peercred

import "fmt"

func inspectFD(uintptr) (Info, error) {
	return Info{}, fmt.Errorf("%w: strict peer metadata is macOS-only in v1", ErrUnsupportedOS)
}
