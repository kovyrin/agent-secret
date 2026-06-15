//go:build !darwin

package peercred

import "fmt"

func inspectFD(uintptr) (Info, error) {
	return Info{}, fmt.Errorf("%w: strict peer metadata is macOS-only in v1", ErrUnsupportedOS)
}

func processAncestry(int) ([]ProcessIdentity, error) {
	return nil, fmt.Errorf("%w: process ancestry is macOS-only in v1", ErrUnsupportedOS)
}
