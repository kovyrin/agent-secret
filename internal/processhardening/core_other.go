//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package processhardening

import "errors"

var ErrUnsupportedPlatform = errors.New("process hardening unsupported on this platform")

func DisableCoreDumps() error {
	return ErrUnsupportedPlatform
}
