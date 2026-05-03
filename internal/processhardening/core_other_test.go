//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package processhardening

import (
	"errors"
	"testing"
)

func TestDisableCoreDumpsUnsupportedPlatform(t *testing.T) {
	t.Parallel()

	if err := DisableCoreDumps(); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("DisableCoreDumps error = %v, want ErrUnsupportedPlatform", err)
	}
}
